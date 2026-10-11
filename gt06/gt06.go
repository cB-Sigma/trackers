// Package gt06 is the GT06 / Concox binary tracker protocol: frame
// reading and writing, decoding into track.Message, and command framing.
// Our own implementation from the published protocol tables.
//
// Frames start with 0x7878 (one length byte) or 0x7979 (two), carry a
// protocol number, content, a serial number and a CRC-ITU (CRC-16/X-25)
// over length..serial, and end with 0x0D0A. Handled: login 0x01 (answered),
// location 0x12 and 0x22 (0x22's re-upload flag marks history), status /
// heartbeat 0x13 (answered), alarm 0x16 and 0x26 (answered), time request
// 0x8A (answered with UTC), information 0x94 (external voltage, status
// text, door, IMSI and ICCID; not answered), command answers 0x15 and
// 0x21. Commands are {"text": "WHERE#"} sent as 0x80 with the sequence as
// server flag; the codec is a track.Correlator, so an answer completes a
// command only when it carries that flag (or a zero flag, from a device
// that does not echo it), and a late answer to an earlier command is not
// taken for the next one's.
//
// Positions without GNSS (lbs.go): the LBS multi-cell frames 0x28, 0x2E
// and 0x24, the LBS extension 0x18 and the LBS+WiFi frame 0x2C (all
// answered like a heartbeat), and the WiFi frames 0x69 and 0x17, whose
// header byte after 0x7878 counts access points instead of giving a length
// and which carry no serial number or CRC (answered with the frame's time).
// Their cells and access points are the record's track.Network, which a
// server may turn into a position with a geolocation service.
//
// The profile (NewCodec; Profile):
//
//	checkCrc: true         # default true; false accepts frames with a bad CRC (some firmware)
//	ackLocation: false     # also answer location frames
//	timezone: UTC          # zone of the device's clock (default UTC)
//	alarms: {"0x13": tamper}   # extra alarm codes → alert type
//	commandLanguage: true  # default true: end a 0x80 command with the language bytes 00 02; false leaves them out
//	failureWords: [error, fail, invalid]   # default; an answer holding one fails the command
//	namedCommands: {engineStop: "DYD,000000#"}   # replaces a named command's text
//
// Named commands (track.Named) are the Concox command texts in a 0x80
// frame, answered like any command: engineStop "RELAY,1#", engineResume
// "RELAY,0#", locate "WHERE#", reboot "RESET#", interval
// "TIMER,<seconds>#" (10 to 18000 s; the reporting interval with the
// ignition on). Older GT06 firmware cuts fuel with "DYD,<password>#" and
// restores it with "HFYD,<password>#": set them in namedCommands.
package gt06

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/cB-Sigma/trackers/track"
)

// Protocol numbers.
const (
	PLogin       = 0x01
	PLocation    = 0x12
	PStatus      = 0x13
	PCmdAnswer   = 0x15
	PAlarm       = 0x16
	PCmdAnswerEx = 0x21
	PLocation2   = 0x22
	PAlarm2      = 0x26
	PCommand     = 0x80
	PTime        = 0x8A
	PInfo        = 0x94 // information transmission (sub-protocol + data)
	PLBSExtend   = 0x18 // LBS extension: serving and neighbour cells
	PLBSMulti3   = 0x24 // LBS multi-cell (third numbering)
	PLBSMulti    = 0x28 // LBS multi-cell
	PLBSWiFi     = 0x2C // LBS multi-cell plus WiFi access points
	PLBSMulti2   = 0x2E // LBS multi-cell (second numbering)
	PWiFi        = 0x17 // WiFi and cells, count-in-header form
	PWiFi2       = 0x69 // WiFi and cells, count-in-header form
)

// Profile is the manufacturer-variation settings.
type Profile struct {
	CheckCRC    *bool             `json:"checkCrc,omitempty"`
	AckLocation bool              `json:"ackLocation,omitempty"`
	Timezone    string            `json:"timezone,omitempty"`
	Alarms      map[string]string `json:"alarms,omitempty"`
	// CommandLanguage (default true) ends a command with the language
	// bytes; some firmware takes commands only without them.
	CommandLanguage *bool    `json:"commandLanguage,omitempty"`
	FailureWords    []string `json:"failureWords,omitempty"`
	// NamedCommands replaces the text of a named command for firmware
	// that differs: {"engineStop": "DYD,000000#", "engineResume": "HFYD,000000#"}.
	// Placeholders {seconds} and {imei}; "" turns one off.
	NamedCommands track.NamedTemplates `json:"namedCommands,omitempty"`
}

type config struct {
	crc    bool
	ackLoc bool
	loc    *time.Location
	alarms map[byte]track.Alert
	lang   bool
	fail   []string
	named  track.NamedTemplates
}

// NewCodec validates a profile (empty for the defaults) and returns a
// factory of codecs, one per connection.
func NewCodec(raw json.RawMessage) (func() track.Codec, error) {
	var p Profile
	if len(raw) > 0 {
		if err := track.StrictJSON(raw, &p); err != nil {
			return nil, err
		}
	}
	c := config{crc: p.CheckCRC == nil || *p.CheckCRC, ackLoc: p.AckLocation, loc: time.UTC, alarms: map[byte]track.Alert{}}
	c.lang = p.CommandLanguage == nil || *p.CommandLanguage
	fw, err := track.FailureWords(p.FailureWords, "error", "fail", "invalid")
	if err != nil {
		return nil, err
	}
	c.fail = fw
	if err := p.NamedCommands.Check(false); err != nil {
		return nil, err
	}
	c.named = p.NamedCommands
	for k, v := range defaultAlarms {
		c.alarms[k] = v
	}
	if p.Timezone != "" {
		l, err := time.LoadLocation(p.Timezone)
		if err != nil {
			return nil, fmt.Errorf("timezone %q: %w", p.Timezone, err)
		}
		c.loc = l
	}
	for k, v := range p.Alarms {
		n, err := strconv.ParseUint(k, 0, 8)
		if err != nil || v == "" {
			return nil, fmt.Errorf("alarms: %q must map a code such as \"0x13\" to an alert type", k)
		}
		c.alarms[byte(n)] = track.Alert{Type: v, Severity: track.SeverityOf(v), Code: fmt.Sprintf("0x%02X", n)}
	}
	return func() track.Codec { return &codec{cfg: c} }, nil
}

var defaultAlarms = map[byte]track.Alert{
	0x01: {Type: "emergency", Severity: track.Critical},
	0x02: {Type: "main-power-removed", Severity: track.Major},
	0x03: {Type: "vibration", Severity: track.Minor},
	0x04: {Type: "geofence-enter", Severity: track.Info},
	0x05: {Type: "geofence-exit", Severity: track.Minor},
	0x06: {Type: "over-speed", Severity: track.Minor},
}

type codec struct {
	cfg  config
	imei string
}

// Frame is a decoded frame.
type Frame struct {
	Ext      bool // 0x7979
	Protocol byte
	Content  []byte
	Serial   uint16
	// Count is set on the WiFi frames (0x69, 0x17) whose header byte is
	// the number of access points; they have no serial number or CRC.
	Count       int
	CountHeader bool
}

// ErrCRC is a frame whose CRC does not match.
var ErrCRC = errors.New("gt06: CRC mismatch")

// ReadFrame reads one frame from a device, skipping bytes until a start
// marker.
func ReadFrame(r *bufio.Reader, checkCRC bool) (*Frame, error) { return readFrame(r, checkCRC, false) }

// ReadServerFrame reads one frame sent by a server (to a device), where the
// WiFi acknowledgement is 0x7878 00, the protocol, six time bytes, 0x0D0A.
func ReadServerFrame(r *bufio.Reader) (*Frame, error) { return readFrame(r, true, true) }

func readFrame(r *bufio.Reader, checkCRC, fromServer bool) (*Frame, error) {
	for {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if b != 0x78 && b != 0x79 {
			continue
		}
		nb, err := r.Peek(1)
		if err != nil {
			return nil, err
		}
		if nb[0] != b {
			continue
		}
		_, _ = r.ReadByte()
		ext := b == 0x79
		var n int
		var lenBytes []byte
		if ext {
			var l [2]byte
			if _, err := io.ReadFull(r, l[:]); err != nil {
				return nil, err
			}
			n, lenBytes = int(binary.BigEndian.Uint16(l[:])), l[:]
		} else {
			l, err := r.ReadByte()
			if err != nil {
				return nil, err
			}
			n, lenBytes = int(l), []byte{l}
			if p, err := r.Peek(1); err == nil && (p[0] == PWiFi || p[0] == PWiFi2) {
				return readWiFiFrame(r, n, fromServer)
			}
		}
		if n < 5 {
			return nil, fmt.Errorf("gt06: length %d is too short", n)
		}
		body := make([]byte, n+2)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, err
		}
		if body[n] != 0x0D || body[n+1] != 0x0A {
			return nil, errors.New("gt06: frame does not end with 0D0A")
		}
		crcIn := append(append([]byte{}, lenBytes...), body[:n-2]...)
		if checkCRC && track.CRCITU(crcIn) != binary.BigEndian.Uint16(body[n-2:n]) {
			return nil, ErrCRC
		}
		return &Frame{Ext: ext, Protocol: body[0], Content: body[1 : n-4], Serial: binary.BigEndian.Uint16(body[n-4 : n-2])}, nil
	}
}

// Encode builds a frame (0x7878 unless the length needs 0x7979).
func Encode(protocol byte, content []byte, serial uint16) []byte {
	n := 1 + len(content) + 4
	var b []byte
	if n > 255 {
		b = []byte{0x79, 0x79, byte(n >> 8), byte(n)}
	} else {
		b = []byte{0x78, 0x78, byte(n)}
	}
	b = append(b, protocol)
	b = append(b, content...)
	b = binary.BigEndian.AppendUint16(b, serial)
	b = binary.BigEndian.AppendUint16(b, track.CRCITU(b[2:]))
	return append(b, 0x0D, 0x0A)
}

func (c *codec) Decode(r *bufio.Reader) (*track.Message, error) {
	f, err := ReadFrame(r, c.cfg.crc)
	if errors.Is(err, ErrCRC) {
		return nil, &track.Skip{Warning: track.Warning{Code: "crcMismatch", Setting: "profile.checkCrc",
			Msg: "A packet whose CRC does not match was dropped. Set profile.checkCrc to false if the device computes it another way."}}
	}
	if err != nil {
		return nil, err
	}
	return c.message(f)
}

// short passes over a well-framed packet whose content is shorter than
// its protocol number needs (a vendor variant); the stream stays in step.
func short(what string, proto byte, n int) error {
	return &track.Skip{Warning: track.Warning{Code: "shortPacket", Detail: fmt.Sprintf("0x%02X, %d bytes", proto, n),
		Msg: "A " + what + " packet shorter than the protocol needs was passed over (the connection stays up)."}}
}

func (c *codec) message(f *Frame) (*track.Message, error) {
	m := &track.Message{IMEI: c.imei}
	ack := func() { m.Reply = Encode(f.Protocol, nil, f.Serial) }
	b := f.Content
	switch f.Protocol {
	case PLogin:
		if len(b) < 8 {
			return nil, short("login", f.Protocol, len(b))
		}
		imei := strings.TrimLeft(fmt.Sprintf("%X", b[:8]), "0")
		if len(imei) < 15 {
			imei = strings.Repeat("0", 15-len(imei)) + imei
		}
		c.imei, m.IMEI, m.Login = imei, imei, true
		ack()
	case PLocation, PLocation2:
		if len(b) < 18 {
			return nil, short("location", f.Protocol, len(b))
		}
		rec := track.Record{Fix: c.gps(b[:6], b[6:18]), Status: map[string]any{}}
		rest := b[18:]
		if len(rest) >= 8 {
			rec.Status["mcc"] = int(binary.BigEndian.Uint16(rest[0:2]))
			rec.Status["mnc"] = int(rest[2])
			rest = rest[8:]
		}
		if f.Protocol == PLocation2 && len(rest) >= 3 {
			rec.Status["ignition"] = rest[0] == 1
			rec.History = rest[2] == 1
		}
		m.Records = []track.Record{rec}
		if c.cfg.ackLoc {
			ack()
		}
	case PStatus:
		if len(b) < 3 {
			return nil, short("status", f.Protocol, len(b))
		}
		st := terminalInfo(b[0])
		st["batteryLevel"], st["gsm"] = int(b[1]), int(b[2])
		m.Records = []track.Record{{Status: st, Alerts: infoAlerts(b[0])}}
		ack()
	case PAlarm, PAlarm2:
		if len(b) < 18+1 {
			return nil, short("alarm", f.Protocol, len(b))
		}
		rec := track.Record{Fix: c.gps(b[:6], b[6:18])}
		rest := b[18:]
		// The LBS block's first byte is its length, itself included.
		if l := int(rest[0]); l > 0 && len(rest) >= l {
			rest = rest[l:]
		}
		if len(rest) >= 4 {
			rec.Status = terminalInfo(rest[0])
			rec.Status["batteryLevel"], rec.Status["gsm"] = int(rest[1]), int(rest[2])
			if a, ok := c.cfg.alarms[rest[3]]; ok {
				if a.Code == "" {
					a.Code = fmt.Sprintf("0x%02X", rest[3])
				}
				rec.Alerts = append(rec.Alerts, a)
			} else if rest[3] != 0 {
				rec.Alerts = append(rec.Alerts, track.Alert{Type: fmt.Sprintf("alarm-0x%02X", rest[3]), Severity: track.Minor, Code: fmt.Sprintf("0x%02X", rest[3])})
			}
		}
		m.Records = []track.Record{rec}
		ack()
	case PInfo:
		if len(b) < 1 {
			return nil, short("information", f.Protocol, len(b))
		}
		m.Records = []track.Record{{Status: infoStatus(b[0], b[1:])}}
	case PLBSExtend, PLBSMulti3, PLBSMulti, PLBSWiFi, PLBSMulti2:
		rec, err := c.lbs(f.Protocol, b)
		if err != nil {
			return nil, err
		}
		m.Records = []track.Record{*rec}
		ack()
	case PWiFi, PWiFi2:
		if !f.CountHeader {
			return nil, track.ErrSkip
		}
		rec, err := c.wifi(f)
		if err != nil {
			return nil, err
		}
		m.Records = []track.Record{*rec}
		m.Reply = WiFiAck(f.Protocol, b[:6])
	case PTime:
		now := time.Now().UTC()
		m.Reply = Encode(PTime, []byte{byte(now.Year() - 2000), byte(now.Month()), byte(now.Day()), byte(now.Hour()), byte(now.Minute()), byte(now.Second())}, f.Serial)
	case PCmdAnswer:
		if len(b) < 5 {
			return nil, short("command answer", f.Protocol, len(b))
		}
		n := min(int(b[0])-4, len(b)-5)
		text := string(b[5 : 5+max(n, 0)])
		m.Response, m.Failed = &text, track.AnswerFailed(text, c.cfg.fail)
		m.Correlation = flagCorrelation(binary.BigEndian.Uint32(b[1:5]))
	case PCmdAnswerEx:
		if len(b) < 5 {
			return nil, short("command answer", f.Protocol, len(b))
		}
		body := b[5:]
		text := string(body)
		if b[4] == 2 && len(body)%2 == 0 {
			u := make([]uint16, len(body)/2)
			for i := range u {
				u[i] = binary.BigEndian.Uint16(body[2*i:])
			}
			text = string(utf16.Decode(u))
		}
		m.Response, m.Failed = &text, track.AnswerFailed(text, c.cfg.fail)
		m.Correlation = flagCorrelation(binary.BigEndian.Uint32(b[0:4]))
	default:
		// A protocol number this codec does not read (a vendor variant):
		// passed over, the connection stays up.
		return nil, &track.Skip{Warning: track.Warning{Code: "unknownPacket", Detail: fmt.Sprintf("0x%02X", f.Protocol),
			Msg: "A packet with a protocol number this codec does not read was passed over."}}
	}
	return m, nil
}

// infoStatus maps a 0x94 information packet's sub-protocol to status
// values: 0x00 external power voltage (hundredths of a volt), 0x04 the
// terminal's status text, 0x05 door status (bit 0: open), 0x0A the IMEI,
// IMSI and ICCID as BCD. Other sub-protocols are kept as hexadecimal.
func infoStatus(sub byte, d []byte) map[string]any {
	bcd := func(b []byte) string { return strings.TrimLeft(fmt.Sprintf("%X", b), "0") }
	switch {
	case sub == 0x00 && len(d) >= 2:
		return map[string]any{"externalVoltage": float64(binary.BigEndian.Uint16(d)) / 100}
	case sub == 0x04:
		return map[string]any{"terminalStatus": strings.TrimRight(string(d), "\x00")}
	case sub == 0x05 && len(d) >= 1:
		return map[string]any{"doorOpen": d[0]&1 == 1}
	case sub == 0x0A && len(d) >= 26:
		return map[string]any{"imsi": bcd(d[8:16]), "iccid": bcd(d[16:26])}
	}
	return map[string]any{fmt.Sprintf("info0x%02X", sub): fmt.Sprintf("%X", d)}
}

// flagCorrelation names the command an answer is to by its server flag; a
// zero flag (a device that does not echo it) names none.
func flagCorrelation(flag uint32) string {
	if flag == 0 {
		return ""
	}
	return strconv.FormatUint(uint64(flag), 10)
}

// Correlation: the answer carries the command's server flag, the sequence.
func (c *codec) Correlation(_ any, seq uint32) (string, bool) {
	return flagCorrelation(seq), false
}

func (c *codec) gps(dt, g []byte) *track.Fix {
	f := &track.Fix{Time: time.Date(2000+int(dt[0]), time.Month(dt[1]), int(dt[2]), int(dt[3]), int(dt[4]), int(dt[5]), 0, c.cfg.loc)}
	sats := int(g[0] & 0x0F)
	f.Sats = &sats
	f.Lat = float64(binary.BigEndian.Uint32(g[1:5])) / 1800000
	f.Lon = float64(binary.BigEndian.Uint32(g[5:9])) / 1800000
	spd := float64(g[9])
	f.Speed = &spd
	cs := binary.BigEndian.Uint16(g[10:12])
	hdg := float64(cs & 0x03FF)
	f.Heading = &hdg
	f.Valid = cs&0x1000 != 0
	if cs&0x0400 == 0 {
		f.Lat = -f.Lat
	}
	if cs&0x0800 != 0 {
		f.Lon = -f.Lon
	}
	return f
}

// terminalInfo reads the terminal information byte of status and alarm
// frames.
func terminalInfo(b byte) map[string]any {
	return map[string]any{
		"armed": b&0x01 != 0, "ignition": b&0x02 != 0, "charging": b&0x04 != 0,
		"gpsTracking": b&0x40 != 0, "fuelCut": b&0x80 != 0,
	}
}

func infoAlerts(b byte) []track.Alert {
	switch (b >> 3) & 0x07 {
	case 4:
		return []track.Alert{{Type: "emergency", Severity: track.Critical, Code: "info-100"}}
	case 3:
		return []track.Alert{{Type: "low-battery", Severity: track.Minor, Code: "info-011"}}
	case 2:
		return []track.Alert{{Type: "main-power-removed", Severity: track.Major, Code: "info-010"}}
	case 1:
		return []track.Alert{{Type: "vibration", Severity: track.Minor, Code: "info-001"}}
	}
	return nil
}

// CommandFrame builds a 0x80 command frame, with the language bytes.
func CommandFrame(text string, flag uint32, serial uint16) []byte {
	return commandFrame(text, flag, serial, true)
}

func commandFrame(text string, flag uint32, serial uint16, lang bool) []byte {
	var c []byte
	c = append(c, byte(4+len(text)))
	c = binary.BigEndian.AppendUint32(c, flag)
	c = append(c, text...)
	if lang {
		c = append(c, 0x00, 0x02) // language: English
	}
	return Encode(PCommand, c, serial)
}

func (c *codec) Command(imei string, content any, seq uint32) ([]byte, bool, error) {
	text, err := commandText(c.cfg.named, imei, content)
	if err != nil {
		return nil, false, err
	}
	if len(text) > 200 {
		return nil, false, errors.New("a GT06 command is at most 200 characters")
	}
	return commandFrame(text, seq, uint16(seq), c.cfg.lang), true, nil
}
