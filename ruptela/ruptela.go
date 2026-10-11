// Package ruptela is the Ruptela binary tracker protocol of the FM-Eco4,
// FM-Pro4, FM-Tco4, HCV5/LCV5, Pro5 and Trace5 devices: packet reading and
// writing, decoding into track.Message, and command framing. Our own
// implementation from Ruptela's public protocol description ("Ruptela
// Protocol", v1.113, copy at
// https://pdfcoffee.com/ruptela-protocol-v1113-pdf-free.html) and SMS
// command list ("SMS Command List", 4th and 5th generation devices, copy at
// https://content.gps-trace.com/assets/634dd45f-332e-4687-9368-dded9923c494).
//
// A device packet is a 2-byte length, the IMEI as an 8-byte number, a
// command ID, the payload and a CRC-16/KERMIT (reflected 0x8408, initial
// value 0, sent big endian) over IMEI..payload; a server packet has no
// IMEI. Read from the device: records 1 and extended records 68 (2-byte
// event and IO IDs; a record split over several headers is merged back by
// its record extension byte), both acknowledged with command 100 (01
// accepted, 00 refused); identification 15 and dynamic identification 18
// (the login: device type, firmware, IMSI; acknowledged with 115);
// heartbeat 16 (acknowledged with 116); diagnostic trouble codes 9
// (acknowledged with 109); the text answer 7 to an SMS command sent over
// GPRS, and the answer 17 to a set-IO-value command. Any other command is
// skipped (track.Skip) with the warning unknownMessage. Records of a
// packet whose "records left" flag is set are the device emptying its
// memory, so they are marked as history.
//
// IO elements become status values: 2-5 din1..din4 (5 is the ignition
// input), 251 virtual ignition, 27 gsm, 29 externalVoltage (V), 30
// batteryVoltage (V), 65 odometer (m); every raw element is also kept
// under "io". A record's event ID is the IO element whose change made the
// record: ignition (5, 251) on/off, 88 GNSS jamming, 134 harsh braking,
// 136 harsh acceleration, 410 towing, 411 impact and 758 tamper become
// alerts; the profile's events add others.
//
// Commands: {"text": "coords"} goes as an SMS command over GPRS (command
// 108, at most MaxText characters) and is answered with command 7;
// {"setIo": {"id": 65, "value": 120000}} is command 117 (set an IO value,
// such as the virtual odometer), answered with command 17 (0 changed, 1
// failed, 2 not supported). Named commands (track.Named): engineStop
// "immobilizer 5", engineResume "resetimmob", locate "coords", reboot
// "reset", each preceded by the command password and a space when there is
// one (CommandWithPassword, or the profile's password); the device's
// immobilizer function must be configured, otherwise it answers that it is
// not and the command fails. Ruptela's public documents do not give the
// parameter ID of the data period, so interval has no default text: set it
// in namedCommands (for example "setcfg <id> {seconds}"). With commandIds
// every text command carries an ID tag the device echoes in its answer;
// the codec is a track.Correlator, so a late answer cannot complete the
// next command. The device's "Use ID in SMS commands" setting must match.
//
// The profile (NewCodec; Profile):
//
//	checkCrc: true            # default true; a packet with a bad CRC is not acknowledged, so the device sends it again
//	io: {"78": temperature1}  # extra IO id → status name (none by default)
//	events: {"14": emergency} # extra event ID → alert type (none by default)
//	namedCommands: {engineStop: "setio 1,2"}   # replace a named command's text per firmware (default none)
//	commandIds: false         # default false; true tags text commands with an ID the device echoes
//	password: ""              # SMS password when the caller gives none (default none)
//	failureWords: [incorrect, error, "not set", "not configured", unknown, invalid, "not supported", permission, failed]   # default; an answer holding one fails the command
package ruptela

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cB-Sigma/trackers/track"
)

// Command IDs from the device.
const (
	CmdRecords     = 1
	CmdSMSAnswer   = 7
	CmdDTC         = 9
	CmdIdent       = 15
	CmdHeartbeat   = 16
	CmdSetIOAnswer = 17
	CmdDynIdent    = 18
	CmdExtRecords  = 68
)

// Command IDs from the server.
const (
	AckRecords   = 100
	SMSCommand   = 108
	AckDTC       = 109
	AckIdent     = 115
	AckHeartbeat = 116
	SetIO        = 117
)

// MaxText is the longest SMS command over GPRS.
const MaxText = 160

// Profile is the manufacturer-variation settings.
type Profile struct {
	// CheckCRC (default true) passes over packets whose CRC does not
	// match without acknowledging them, so the device sends them again.
	CheckCRC *bool `json:"checkCrc,omitempty"`
	// IO maps further IO element IDs to status names (their raw value).
	IO map[string]string `json:"io,omitempty"`
	// Events maps further event IDs to alert types.
	Events map[string]string `json:"events,omitempty"`
	// NamedCommands replaces the text of a named command for firmware that
	// differs ("" turns it off), with {seconds}, {password} and {imei}.
	NamedCommands track.NamedTemplates `json:"namedCommands,omitempty"`
	// CommandIDs (default false) adds an ID tag to every text command; the
	// device echoes it in its answer when its "Use ID in SMS commands"
	// setting is on (and then ignores commands without one).
	CommandIDs bool `json:"commandIds,omitempty"`
	// Password is the SMS password put before named commands of devices
	// without their own commandPassword ("" none).
	Password string `json:"password,omitempty"`
	// FailureWords are the words whose presence in an answer fails the
	// command.
	FailureWords []string `json:"failureWords,omitempty"`
}

// Named commands.
var (
	// Interval bounds the interval command, in seconds.
	Interval = track.IntervalRange{Min: 1, Max: 65535}
	// NamedActions are the named commands Ruptela has a default text for;
	// interval needs a profile template.
	NamedActions = []string{track.ActionEngineStop, track.ActionEngineResume, track.ActionLocate, track.ActionReboot}
)

// defaultNamed are the named commands' texts (SMS command list: immobilizer,
// resetimmob, coords, reset).
var defaultNamed = map[string]string{
	track.ActionEngineStop:   "immobilizer 5",
	track.ActionEngineResume: "resetimmob",
	track.ActionLocate:       "coords",
	track.ActionReboot:       "reset",
}

type config struct {
	crc      bool
	io       map[uint16]string
	events   map[uint16]string
	named    track.NamedTemplates
	ids      bool
	salt     string // the first half of command ID tags, new per start
	password string
	fail     []string
}

// NewCodec validates a profile (empty for the defaults) and returns a
// factory of codecs, one per connection.
func NewCodec(raw json.RawMessage) (func() track.Codec, error) {
	var p Profile
	if err := track.StrictJSON(raw, &p); err != nil {
		return nil, err
	}
	c := config{crc: p.CheckCRC == nil || *p.CheckCRC, io: map[uint16]string{}, events: map[uint16]string{},
		named: p.NamedCommands, ids: p.CommandIDs, password: p.Password}
	if err := p.NamedCommands.Check(true); err != nil {
		return nil, err
	}
	fw, err := track.FailureWords(p.FailureWords, "incorrect", "error", "not set", "not configured", "unknown", "invalid",
		"not supported", "permission", "failed")
	if err != nil {
		return nil, err
	}
	c.fail = fw
	for k, v := range p.IO {
		n, err := strconv.ParseUint(k, 10, 16)
		if err != nil || v == "" {
			return nil, fmt.Errorf("io: %q must map an IO id (0 to 65535) to a status name", k)
		}
		c.io[uint16(n)] = v
	}
	for k, v := range p.Events {
		n, err := strconv.ParseUint(k, 10, 16)
		if err != nil || v == "" {
			return nil, fmt.Errorf("events: %q must map an event ID (0 to 65535) to an alert type", k)
		}
		c.events[uint16(n)] = v
	}
	var s [4]byte
	_, _ = rand.Read(s[:])
	c.salt = strings.ToUpper(hex.EncodeToString(s[:]))
	return func() track.Codec { return &codec{cfg: c} }, nil
}

type codec struct {
	cfg  config
	imei string
}

// ---- framing ----------------------------------------------------------------

// CRC is the protocol's CRC-16 (KERMIT: reflected 0x8408, initial value 0,
// no final XOR), as the protocol's C example computes it.
func CRC(b []byte) uint16 {
	var c uint16
	for _, v := range b {
		c ^= uint16(v)
		for range 8 {
			if c&1 != 0 {
				c = c>>1 ^ 0x8408
			} else {
				c >>= 1
			}
		}
	}
	return c
}

// ServerFrame builds a server packet: length, command, payload, CRC.
func ServerFrame(cmd byte, payload []byte) []byte {
	body := append([]byte{cmd}, payload...)
	out := binary.BigEndian.AppendUint16(nil, uint16(len(body)))
	out = append(out, body...)
	return binary.BigEndian.AppendUint16(out, CRC(body))
}

// DeviceFrame builds a device packet: length, IMEI, command, payload, CRC.
func DeviceFrame(imei uint64, cmd byte, payload []byte) []byte {
	body := binary.BigEndian.AppendUint64(nil, imei)
	body = append(body, cmd)
	body = append(body, payload...)
	out := binary.BigEndian.AppendUint16(nil, uint16(len(body)))
	out = append(out, body...)
	return binary.BigEndian.AppendUint16(out, CRC(body))
}

// ErrCRC is a packet whose CRC does not match.
var ErrCRC = errors.New("ruptela: CRC mismatch")

// maxPacket bounds the length field (the protocol's payload is at most
// about 1 KB; extended records and files stay well below this).
const maxPacket = 4096

// readPacket reads one packet; body is everything between the length and
// the CRC. A CRC mismatch returns the body with ErrCRC.
func readPacket(r *bufio.Reader, minLen int) ([]byte, error) {
	var l [2]byte
	if _, err := io.ReadFull(r, l[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(l[:]))
	if n < minLen || n > maxPacket {
		return nil, fmt.Errorf("ruptela: packet length %d", n)
	}
	b := make([]byte, n+2)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	if CRC(b[:n]) != binary.BigEndian.Uint16(b[n:]) {
		return b[:n], ErrCRC
	}
	return b[:n], nil
}

// ReadServerFrame reads a packet a server sent (for simulators): its
// command and payload.
func ReadServerFrame(r *bufio.Reader) (byte, []byte, error) {
	b, err := readPacket(r, 1)
	if err != nil {
		return 0, nil, err
	}
	return b[0], b[1:], nil
}

// ---- decoding ---------------------------------------------------------------

func ack(cmd, v byte) []byte { return ServerFrame(cmd, []byte{v}) }

func (c *codec) Decode(r *bufio.Reader) (*track.Message, error) {
	b, err := readPacket(r, 9)
	if errors.Is(err, ErrCRC) {
		if c.cfg.crc {
			return nil, &track.Skip{Warning: track.Warning{Code: "crcMismatch", Setting: "profile.checkCrc",
				Msg: "A packet whose CRC does not match was not acknowledged (the device sends it again). Set profile.checkCrc to false if the device computes it another way."}}
		}
	} else if err != nil {
		return nil, err
	}
	imei := strconv.FormatUint(binary.BigEndian.Uint64(b[:8]), 10)
	cmd, p := b[8], b[9:]
	if c.imei == "" {
		c.imei = imei
	}
	m := &track.Message{IMEI: imei}
	switch cmd {
	case CmdRecords, CmdExtRecords:
		recs, err := c.records(p, cmd == CmdExtRecords)
		if err != nil {
			// Read whole, so the stream stays in step; refused, so the
			// device keeps the records and sends them again.
			return &track.Message{IMEI: imei, Kind: "normal", Reply: ack(AckRecords, 0), Reject: ack(AckRecords, 0),
				Warnings: []track.Warning{{Code: "unknownPacket", Detail: err.Error(),
					Msg: "A records packet that could not be read was refused (the device sends it again later; the connection stays up)."}}}, nil
		}
		m.Records, m.Kind = recs, "normal"
		for _, r := range recs {
			for _, a := range r.Alerts {
				if a.Type == "emergency" {
					m.Kind = "emergency"
				}
			}
		}
		m.Reply, m.Reject = ack(AckRecords, 1), ack(AckRecords, 0)
	case CmdIdent:
		m.Login, m.Kind = true, "login"
		m.Records = []track.Record{{Status: identification(p), Time: time.Now()}}
		m.Reply, m.Reject = ack(AckIdent, 1), ack(AckIdent, 2)
	case CmdDynIdent:
		m.Login, m.Kind = true, "login"
		m.Records = []track.Record{{Status: dynIdentification(p), Time: time.Now()}}
		m.Reply, m.Reject = ack(AckIdent, 1), ack(AckIdent, 2)
	case CmdHeartbeat:
		m.Kind = "health"
		m.Reply, m.Reject = ack(AckHeartbeat, 1), ack(AckHeartbeat, 0)
	case CmdDTC:
		m.Kind = "health"
		m.Records = []track.Record{{Status: map[string]any{"dtc": fmt.Sprintf("%X", p)}, Time: time.Now()}}
		m.Reply = ack(AckDTC, 1)
	case CmdSMSAnswer:
		text := string(p)
		m.Kind = "response"
		m.Response = &text
		m.Failed = track.AnswerFailed(text, c.cfg.fail)
		m.Correlation = answerID(text)
	case CmdSetIOAnswer:
		if len(p) < 1 {
			return nil, &track.Skip{Warning: track.Warning{Code: "shortPacket", Detail: "set IO value answer without a result",
				Msg: "A set-IO-value answer without its result byte was passed over."}}
		}
		var text string
		switch p[0] {
		case 0:
			text = "IO value changed"
		case 1:
			text, m.Failed = "the device could not change the IO value", true
		case 2:
			text, m.Failed = "the device does not support setting this IO value", true
		default:
			text, m.Failed = fmt.Sprintf("the device answered with result %d", p[0]), true
		}
		m.Kind = "response"
		m.Response = &text
		m.Details = map[string]any{"result": int(p[0])}
	default:
		return nil, &track.Skip{Warning: track.Warning{Code: "unknownMessage", Detail: fmt.Sprintf("command %d", cmd),
			Msg: "A Ruptela packet of a command this codec does not read was passed over (the connection stays up)."}}
	}
	return m, nil
}

var idTag = regexp.MustCompile(`\bID([0-9A-Fa-f]{16,32})\b`)

// answerID is the ID tag an answer carries ("" none).
func answerID(text string) string {
	all := idTag.FindAllStringSubmatch(text, -1)
	if len(all) == 0 {
		return ""
	}
	return "ID" + strings.ToUpper(all[len(all)-1][1])
}

func identification(p []byte) map[string]any {
	st := map[string]any{}
	if len(p) >= 15 {
		st["deviceType"] = strings.TrimRight(string(p[0:4]), "\x00 ")
		st["firmware"] = strings.TrimRight(string(p[4:15]), "\x00 ")
	}
	if len(p) >= 23 {
		st["imsi"] = strconv.FormatUint(binary.BigEndian.Uint64(p[15:23]), 10)
	}
	if len(p) >= 27 {
		st["operator"] = binary.BigEndian.Uint32(p[23:27])
	}
	return st
}

func dynIdentification(p []byte) map[string]any {
	st := map[string]any{}
	if len(p) < 2 {
		return st
	}
	n, p := int(p[1]), p[2:]
	for i := 0; i < n && len(p) >= 2; i++ {
		id, l := p[0], int(p[1])
		if len(p) < 2+l {
			break
		}
		v := p[2 : 2+l]
		p = p[2+l:]
		switch id {
		case 1:
			st["deviceType"] = strings.TrimRight(string(v), "\x00 ")
		case 2:
			st["firmware"] = strings.TrimRight(string(v), "\x00 ")
		case 3:
			if l == 8 {
				st["imsi"] = strconv.FormatUint(binary.BigEndian.Uint64(v), 10)
			}
		case 4:
			if l == 4 {
				st["operator"] = binary.BigEndian.Uint32(v)
			}
		}
	}
	return st
}

type rd struct {
	b   []byte
	err error
}

func (r *rd) take(n int) []byte {
	if r.err != nil || len(r.b) < n {
		r.err = errors.New("ruptela: record data is truncated")
		return make([]byte, n)
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}
func (r *rd) u8() uint64  { return uint64(r.take(1)[0]) }
func (r *rd) u16() uint64 { return uint64(binary.BigEndian.Uint16(r.take(2))) }
func (r *rd) u32() uint64 { return uint64(binary.BigEndian.Uint32(r.take(4))) }
func (r *rd) u64() uint64 { return binary.BigEndian.Uint64(r.take(8)) }

// header is a record's fixed part.
type header struct {
	ts, tsExt, ext, prio, sats, hdop, event uint64
	lon, lat                                int32
	alt                                     int16
	angle, speed                            uint64
}

// records reads records left, count and the records; ext is command 68.
func (c *codec) records(p []byte, ext bool) ([]track.Record, error) {
	r := &rd{b: p}
	left := r.u8()
	n := int(r.u8())
	var out []track.Record
	var cur *track.Record
	var curIO map[uint16]uint64
	var curHdr header
	idw := r.u8
	if ext {
		idw = r.u16
	}
	for i := 0; i < n && r.err == nil; i++ {
		var h header
		h.ts = r.u32()
		h.tsExt = r.u8()
		if ext {
			h.ext = r.u8()
		}
		h.prio = r.u8()
		h.lon = int32(r.u32())
		h.lat = int32(r.u32())
		h.alt = int16(r.u16())
		h.angle = r.u16()
		h.sats = r.u8()
		h.speed = r.u16()
		h.hdop = r.u8()
		if ext {
			h.event = r.u16()
		} else {
			h.event = r.u8()
		}
		ios := map[uint16]uint64{}
		for _, size := range []int{1, 2, 4, 8} {
			cnt := int(r.u8())
			for j := 0; j < cnt && r.err == nil; j++ {
				id := uint16(idw())
				var v uint64
				switch size {
				case 1:
					v = r.u8()
				case 2:
					v = r.u16()
				case 4:
					v = r.u32()
				case 8:
					v = r.u64()
				}
				ios[id] = v
			}
		}
		// A record split over several headers (record extension: high
		// digit the last index, low digit this one's) is merged back.
		if cur != nil && h.ts == curHdr.ts && h.tsExt == curHdr.tsExt && h.ext>>4 == curHdr.ext>>4 && h.ext>>4 > 0 {
			for k, v := range ios {
				curIO[k] = v
			}
		} else {
			if cur != nil {
				out = append(out, c.finish(cur, curHdr, curIO, left == 1))
			}
			cur, curHdr, curIO = &track.Record{}, h, ios
		}
	}
	if r.err != nil {
		return nil, r.err
	}
	if cur != nil {
		out = append(out, c.finish(cur, curHdr, curIO, left == 1))
	}
	return out, nil
}

// knownIO are the IO elements read into named status values.
var knownIO = map[uint16]struct {
	name string
	div  float64 // 0: integer as is; -1: boolean; else value/div
}{
	2: {"din1", -1}, 3: {"din2", -1}, 4: {"din3", -1}, 5: {"din4", -1},
	27: {"gsm", 0}, 29: {"externalVoltage", 1000}, 30: {"batteryVoltage", 1000}, 65: {"odometer", 0},
}

func (c *codec) finish(rec *track.Record, h header, ios map[uint16]uint64, history bool) track.Record {
	t := time.Unix(int64(h.ts), 0).UTC()
	lat, lon := float64(h.lat)/1e7, float64(h.lon)/1e7
	alt := float64(h.alt) / 10
	ang := float64(h.angle) / 100
	spd := float64(h.speed)
	hdop := float64(h.hdop) / 10
	sats := int(h.sats)
	rec.Fix = &track.Fix{Time: t, Lat: lat, Lon: lon, Alt: &alt, Heading: &ang, Speed: &spd, Sats: &sats, HDOP: &hdop,
		Valid: sats > 0 && (lat != 0 || lon != 0)}
	rec.Time, rec.History = t, history
	raw := map[string]any{}
	st := map[string]any{"io": raw, "priority": int(h.prio), "event": int(h.event)}
	for id, v := range ios {
		raw[strconv.Itoa(int(id))] = v
		if d, ok := knownIO[id]; ok {
			switch {
			case d.div < 0:
				st[d.name] = v != 0
			case d.div > 0:
				st[d.name] = float64(v) / d.div
			default:
				st[d.name] = v
			}
		}
		if name, ok := c.cfg.io[id]; ok {
			st[name] = v
		}
	}
	ign, hasIgn := ignition(ios)
	if hasIgn {
		st["ignition"] = ign
	}
	rec.Status = st
	rec.Alerts = c.alerts(uint16(h.event), ios)
	return *rec
}

// ignition reads the ignition from the virtual ignition element (251) or
// the ignition input DIN4 (5).
func ignition(ios map[uint16]uint64) (bool, bool) {
	for _, id := range []uint16{251, 5} {
		if v, ok := ios[id]; ok {
			return v != 0, true
		}
	}
	return false, false
}

func (c *codec) alerts(event uint16, ios map[uint16]uint64) []track.Alert {
	var out []track.Alert
	code := "event-" + strconv.Itoa(int(event))
	v, has := ios[event]
	switch event {
	case 5, 251:
		if has && v != 0 {
			out = append(out, track.NewAlert("ignition-on", code))
		} else if has {
			out = append(out, track.NewAlert("ignition-off", code))
		}
	case 88:
		if v != 0 {
			out = append(out, track.NewAlert("gnss-jamming", code))
		}
	case 134:
		if v != 0 {
			out = append(out, track.NewAlert("harsh-braking", code))
		}
	case 136:
		if v != 0 {
			out = append(out, track.NewAlert("harsh-acceleration", code))
		}
	case 410:
		if v != 0 {
			out = append(out, track.NewAlert("towing", code))
		}
	case 411:
		if v != 0 {
			out = append(out, track.NewAlert("impact", code))
		}
	case 758:
		if has && v == 1 {
			out = append(out, track.NewAlert("tamper", code))
		}
	}
	if typ, ok := c.cfg.events[event]; ok {
		out = append(out, track.NewAlert(typ, code))
	}
	return out
}

// ---- commands ---------------------------------------------------------------

// SMSFrame is an SMS command sent over GPRS (command 108).
func SMSFrame(text string) []byte { return ServerFrame(SMSCommand, []byte(text)) }

// SetIOFrame is a set-IO-value command (117): the IO ID and the value, 4
// bytes each.
func SetIOFrame(id, value uint32) []byte {
	p := binary.BigEndian.AppendUint32(nil, id)
	return ServerFrame(SetIO, binary.BigEndian.AppendUint32(p, value))
}

func (c *codec) Command(imei string, content any, seq uint32) ([]byte, bool, error) {
	return c.CommandWithPassword(imei, "", content, seq)
}

// CommandWithPassword frames a command with the device's command password
// ("" for the profile's password, if any).
func (c *codec) CommandWithPassword(imei, password string, content any, seq uint32) ([]byte, bool, error) {
	if m, ok := content.(map[string]any); ok {
		if s, has := m["setIo"]; has {
			id, v, err := readSetIO(s, len(m))
			if err != nil {
				return nil, false, err
			}
			return SetIOFrame(id, v), true, nil
		}
	}
	text, err := c.text(password, imei, content)
	if err != nil {
		return nil, false, err
	}
	if c.cfg.ids {
		text += " " + c.tag(seq)
	}
	if len(text) > MaxText {
		return nil, false, fmt.Errorf("the command is %d characters; Ruptela devices take at most %d over GPRS", len(text), MaxText)
	}
	return SMSFrame(text), true, nil
}

func (c *codec) text(password, imei string, content any) (string, error) {
	n, named, err := track.ReadNamed(content)
	if err != nil {
		return "", err
	}
	if !named {
		return track.CommandText(content)
	}
	pw := password
	if pw == "" {
		pw = c.cfg.password
	}
	if _, own := c.cfg.named[n.Action]; own {
		return track.NamedText("ruptela", n, c.cfg.named, defaultNamed, Interval, imei, pw)
	}
	if n.Action == track.ActionInterval {
		return "", track.Unsupported("ruptela", n.Action,
			"Ruptela's public documents do not name the data period parameter; set profile.namedCommands.interval to the device's setcfg command, or change the period in the configurator")
	}
	t, err := track.NamedText("ruptela", n, c.cfg.named, defaultNamed, Interval, imei, pw)
	if err != nil {
		return "", err
	}
	if pw != "" {
		t = pw + " " + t
	}
	return t, nil
}

func readSetIO(s any, members int) (uint32, uint32, error) {
	const form = `setIo is {"id": <IO id>, "value": <whole number>}`
	m, ok := s.(map[string]any)
	if !ok || members != 1 || len(m) != 2 {
		return 0, 0, errors.New(form)
	}
	id, ok1 := whole(m["id"], 65535)
	v, ok2 := whole(m["value"], 4294967295)
	if !ok1 || !ok2 {
		return 0, 0, errors.New(form + "; id is 0 to 65535 and value 0 to 4294967295")
	}
	return uint32(id), uint32(v), nil
}

func whole(v any, max float64) (float64, bool) {
	f, ok := v.(float64)
	if !ok {
		if i, isInt := v.(int); isInt {
			f, ok = float64(i), true
		}
	}
	return f, ok && f >= 0 && f <= max && f == float64(int64(f))
}

// tag is the ID tag of the command with this sequence number: the codec's
// start salt and the sequence, 16 hex digits.
func (c *codec) tag(seq uint32) string { return fmt.Sprintf("ID%s%08X", c.cfg.salt, seq) }

// Correlation: with commandIds a text command's answer carries its ID tag.
// An answer without one (some commands never echo it) is still taken.
func (c *codec) Correlation(content any, seq uint32) (string, bool) {
	if !c.cfg.ids {
		return "", false
	}
	if m, ok := content.(map[string]any); ok {
		if _, has := m["setIo"]; has {
			return "", false
		}
	}
	return c.tag(seq), false
}
