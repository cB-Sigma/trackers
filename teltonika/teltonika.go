// Package teltonika is the Teltonika AVL protocol: packet reading and
// writing, decoding into track.Message, and command framing. Our own
// implementation from Teltonika's public protocol description.
//
// Codec 8 and Codec 8 Extended data over TCP (IMEI handshake answered 0x01
// or 0x00, CRC-16/IBM over codec..count, answered with the number of
// records accepted) and UDP (the codec is a track.DatagramCodec; packet ID
// and AVL packet ID echoed in the acknowledgement), Codec 16 data (2-byte
// IO IDs, generation type), Codec 13 timestamped device messages (the
// status "message"), and Codec 12 or Codec 14 (IMEI-addressed; profile
// commandCodec: 14) commands and answers over TCP. A Codec 14 "IMEI does
// not match" answer fails the command.
//
// GPS elements become the fix; IO elements become status values (239
// ignition, 240 movement, 21 gsm, 66 externalVoltage, 67 batteryVoltage,
// 113 batteryLevel, 69 gnssStatus, 181 pdop, 182 hdop, 16 odometer, 1
// din1, 179 dout1) plus every raw element under "io". A record's event IO
// element and priority become alerts: priority 2 (panic) emergency; 253
// harsh acceleration, braking or cornering; 255 over-speed; 252 main power
// removed or restored; 247 impact; 246 towing; 249 and 318 GNSS jamming;
// 239 ignition on/off.
//
// The profile (NewCodec; Profile):
//
//	checkCrc: true         # default true; a frame with a bad CRC is not acknowledged, so the device resends
//	io: {"78": iButton}    # extra IO id → status name
//	commandCodec: 12       # default 12; 14 sends IMEI-addressed commands
//	failureWords: [error, unknown, fail]   # default; an answer holding one fails the command
//	namedCommands: {engineStop: "setdigout ?1"}   # replaces a named command's text
//
// Named commands (track.Named) are SMS/GPRS command texts in Codec 12 or
// 14: engineStop "setdigout 1" (DOUT1 on), engineResume "setdigout 0",
// locate "getrecord" (a high-priority record now), reboot "cpureset". The
// reporting interval is a model's own parameter (setparam <id>:<value>)
// and has no default: set namedCommands.interval for the model.
//
// Commands: {"text": "getinfo"} (any SMS/GPRS command) as Codec 12; the
// answer is the message's Response. A Codec 12 or 14 answer does not name
// its command, so the codec is not a track.Correlator: a server should
// hold the next command to a tracker until a late answer to a timed-out
// one came or a timeout passed.
package teltonika

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/cB-Sigma/trackers/track"
)

// Codec IDs.
const (
	Codec8   = 0x08
	Codec8E  = 0x8E
	Codec12  = 0x0C
	Codec13  = 0x0D // device message with a timestamp (one way)
	Codec14  = 0x0E // IMEI-addressed command and answer
	Codec16  = 0x10 // AVL data with 2-byte IO IDs and a generation type
	TypeCmd  = 0x05
	TypeResp = 0x06
	// TypeNotMine is a Codec 14 answer: the command's IMEI is not the
	// device's.
	TypeNotMine = 0x11
)

// Profile is the manufacturer-variation settings.
type Profile struct {
	CheckCRC *bool             `json:"checkCrc,omitempty"`
	IO       map[string]string `json:"io,omitempty"`
	// CommandCodec is 12 (default) or 14 (the command carries the IMEI and
	// a device with another IMEI refuses it).
	CommandCodec int      `json:"commandCodec,omitempty"`
	FailureWords []string `json:"failureWords,omitempty"`
	// NamedCommands replaces the text of a named command: {"engineStop":
	// "setdigout ?1"} for a relay on DOUT2, {"interval": "setparam 10050:{seconds}"}.
	// Placeholders {seconds} and {imei}; "" turns one off.
	NamedCommands track.NamedTemplates `json:"namedCommands,omitempty"`
}

type config struct {
	crc   bool
	io    map[uint16]string
	cmd14 bool
	fail  []string
	named track.NamedTemplates
}

// NewCodec validates a profile (empty for the defaults) and returns a
// factory of codecs, one per connection or UDP peer.
func NewCodec(raw json.RawMessage) (func() track.Codec, error) {
	var p Profile
	if err := track.StrictJSON(raw, &p); err != nil {
		return nil, err
	}
	c := config{crc: p.CheckCRC == nil || *p.CheckCRC, io: map[uint16]string{}}
	switch p.CommandCodec {
	case 0, 12:
	case 14:
		c.cmd14 = true
	default:
		return nil, fmt.Errorf("commandCodec %d is not 12 or 14", p.CommandCodec)
	}
	fw, err := track.FailureWords(p.FailureWords, "error", "unknown", "fail")
	if err != nil {
		return nil, err
	}
	c.fail = fw
	if err := p.NamedCommands.Check(false); err != nil {
		return nil, err
	}
	c.named = p.NamedCommands
	for k, v := range knownIO {
		c.io[k] = v.name
	}
	for k, v := range p.IO {
		n, err := strconv.ParseUint(k, 10, 16)
		if err != nil || v == "" {
			return nil, fmt.Errorf("io: %q must map an IO id to a status name", k)
		}
		c.io[uint16(n)] = v
	}
	return func() track.Codec { return &codec{cfg: c} }, nil
}

type ioDef struct {
	name string
	div  float64 // 0: integer as is; -1: boolean; else value/div
}

var knownIO = map[uint16]ioDef{
	239: {"ignition", -1}, 240: {"movement", -1}, 21: {"gsm", 0}, 66: {"externalVoltage", 1000},
	67: {"batteryVoltage", 1000}, 113: {"batteryLevel", 0}, 69: {"gnssStatus", 0}, 181: {"pdop", 10},
	182: {"hdop", 10}, 16: {"odometer", 0}, 1: {"din1", -1}, 179: {"dout1", -1}, 68: {"batteryCurrent", 1000},
}

type codec struct {
	cfg  config
	imei string
}

// ---- TCP --------------------------------------------------------------------

const maxData = 1 << 16

func (c *codec) Decode(r *bufio.Reader) (*track.Message, error) {
	if c.imei == "" {
		var l [2]byte
		if _, err := io.ReadFull(r, l[:]); err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(l[:]))
		if n < 8 || n > 20 {
			return nil, fmt.Errorf("teltonika: IMEI length %d", n)
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(r, b); err != nil {
			return nil, err
		}
		c.imei = string(b)
		return &track.Message{IMEI: c.imei, Login: true, Reply: []byte{0x01}, Reject: []byte{0x00}}, nil
	}
	var h [8]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	if binary.BigEndian.Uint32(h[:4]) != 0 {
		return nil, errors.New("teltonika: missing zero preamble")
	}
	n := int(binary.BigEndian.Uint32(h[4:]))
	if n < 3 || n > maxData {
		return nil, fmt.Errorf("teltonika: data length %d", n)
	}
	data := make([]byte, n+4)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, err
	}
	if c.cfg.crc && uint32(track.CRC16IBM(data[:n])) != binary.BigEndian.Uint32(data[n:]) {
		// Not acknowledged: the device sends it again.
		return nil, &track.Skip{Warning: track.Warning{Code: "crcMismatch", Setting: "profile.checkCrc",
			Msg: "A packet whose CRC does not match was not acknowledged (the device sends it again). Set profile.checkCrc to false if the device computes it another way."}}
	}
	data = data[:n]
	m := &track.Message{IMEI: c.imei}
	switch data[0] {
	case Codec8, Codec8E, Codec16:
		recs, err := c.records(data)
		if err != nil {
			// The packet was read whole, so the stream stays in step; it is
			// not acknowledged and the device sends it again.
			return nil, &track.Skip{Warning: track.Warning{Code: "avlUnreadable", Detail: err.Error(),
				Msg: "AVL data that could not be read was not acknowledged (the device sends it again; the connection stays up)."}}
		}
		m.Records = recs
		m.Reply = binary.BigEndian.AppendUint32(nil, uint32(len(recs)))
	case Codec12:
		text, typ, err := ParseCodec12(data)
		if err != nil {
			return nil, &track.Skip{Warning: track.Warning{Code: "messageUnreadable", Detail: err.Error(),
				Msg: "A Teltonika text message that could not be read was passed over (the connection stays up)."}}
		}
		if typ != TypeResp {
			return nil, track.ErrSkip
		}
		m.Response = &text
		m.Failed = track.AnswerFailed(text, c.cfg.fail)
	case Codec13:
		// A device message with its own time; it needs no answer.
		text, at, err := ParseCodec13(data)
		if err != nil {
			return nil, &track.Skip{Warning: track.Warning{Code: "messageUnreadable", Detail: err.Error(),
				Msg: "A Teltonika text message that could not be read was passed over (the connection stays up)."}}
		}
		// Not a command's answer: only the status records it.
		m.Records = []track.Record{{Status: map[string]any{"message": text}, Time: at}}
	case Codec14:
		text, typ, err := ParseCodec14(data)
		if err != nil {
			return nil, &track.Skip{Warning: track.Warning{Code: "messageUnreadable", Detail: err.Error(),
				Msg: "A Teltonika text message that could not be read was passed over (the connection stays up)."}}
		}
		switch typ {
		case TypeResp:
		case TypeNotMine:
			text, m.Failed = "the device refused the command: its IMEI is not the command's", true
		default:
			return nil, track.ErrSkip
		}
		m.Response = &text
		if typ == TypeResp {
			m.Failed = track.AnswerFailed(text, c.cfg.fail)
		}
	default:
		// A codec this codec does not read (a newer firmware's): the
		// packet was read whole, so it is passed over.
		return nil, &track.Skip{Warning: track.Warning{Code: "unknownCodec", Detail: fmt.Sprintf("0x%02X", data[0]),
			Msg: "A packet in a Teltonika codec this codec does not read was passed over (the connection stays up)."}}
	}
	return m, nil
}

// ParseCodec13 reads a Codec 13 data field: quantity, type, size (the
// timestamp's 4 bytes plus the text), a Unix timestamp in seconds, the
// text and the quantity again.
func ParseCodec13(d []byte) (string, time.Time, error) {
	if len(d) < 12 || d[0] != Codec13 {
		return "", time.Time{}, errors.New("teltonika: not a Codec 13 message")
	}
	n := int(binary.BigEndian.Uint32(d[3:7]))
	if n < 4 || 7+n+1 > len(d) {
		return "", time.Time{}, errors.New("teltonika: Codec 13 size overruns the packet")
	}
	at := time.Unix(int64(binary.BigEndian.Uint32(d[7:11])), 0).UTC()
	return string(d[11 : 7+n]), at, nil
}

// ParseCodec14 reads a Codec 14 data field: quantity, type, size (the
// IMEI's 8 bytes plus the text), the IMEI as 8 BCD bytes, the text and the
// quantity again. It returns the text and the type.
func ParseCodec14(d []byte) (string, byte, error) {
	if len(d) < 8 || d[0] != Codec14 {
		return "", 0, errors.New("teltonika: not a Codec 14 message")
	}
	n := int(binary.BigEndian.Uint32(d[3:7]))
	if 7+n+1 > len(d) {
		return "", 0, errors.New("teltonika: Codec 14 size overruns the packet")
	}
	if n < 8 {
		return "", d[2], nil
	}
	return string(d[15 : 7+n]), d[2], nil
}

// Codec14Frame builds a Codec 14 command (TCP) for the device with this
// IMEI: the IMEI goes as 8 bytes of BCD with a leading zero digit.
func Codec14Frame(imei, text string) ([]byte, error) {
	digits := fmt.Sprintf("%016s", imei)
	if len(digits) != 16 {
		return nil, fmt.Errorf("teltonika: IMEI %q is longer than 16 digits", imei)
	}
	var id [8]byte
	for i := 0; i < 8; i++ {
		hi, lo := digits[2*i]-'0', digits[2*i+1]-'0'
		if hi > 9 || lo > 9 {
			return nil, fmt.Errorf("teltonika: IMEI %q is not digits", imei)
		}
		id[i] = hi<<4 | lo
	}
	d := []byte{Codec14, 0x01, TypeCmd}
	d = binary.BigEndian.AppendUint32(d, uint32(8+len(text)))
	d = append(d, id[:]...)
	d = append(d, text...)
	d = append(d, 0x01)
	out := make([]byte, 4, 12+len(d))
	out = binary.BigEndian.AppendUint32(out, uint32(len(d)))
	out = append(out, d...)
	return binary.BigEndian.AppendUint32(out, uint32(track.CRC16IBM(d))), nil
}

// ParseCodec12 reads a Codec 12 data field (codec..count2) and returns
// the text and message type.
func ParseCodec12(d []byte) (string, byte, error) {
	if len(d) < 8 || d[0] != Codec12 {
		return "", 0, errors.New("teltonika: not a Codec 12 message")
	}
	typ := d[2]
	n := int(binary.BigEndian.Uint32(d[3:7]))
	if 7+n+1 > len(d) {
		return "", 0, errors.New("teltonika: Codec 12 size overruns the packet")
	}
	return string(d[7 : 7+n]), typ, nil
}

// Codec12 builds a Codec 12 frame (TCP) of the given type.
func Codec12Frame(typ byte, text string) []byte {
	d := []byte{Codec12, 0x01, typ}
	d = binary.BigEndian.AppendUint32(d, uint32(len(text)))
	d = append(d, text...)
	d = append(d, 0x01)
	out := make([]byte, 4, 12+len(d))
	out = binary.BigEndian.AppendUint32(out, uint32(len(d)))
	out = append(out, d...)
	return binary.BigEndian.AppendUint32(out, uint32(track.CRC16IBM(d)))
}

func (c *codec) Command(imei string, content any, _ uint32) ([]byte, bool, error) {
	text, err := commandText(c.cfg.named, imei, content)
	if err != nil {
		return nil, false, err
	}
	if c.cfg.cmd14 {
		f, err := Codec14Frame(imei, text)
		return f, true, err
	}
	return Codec12Frame(TypeCmd, text), true, nil
}

// ---- UDP --------------------------------------------------------------------

// DecodeDatagram reads a UDP AVL packet and builds its acknowledgement.
func (c *codec) DecodeDatagram(b []byte) ([]*track.Message, error) {
	if len(b) < 9 {
		return nil, errors.New("teltonika: short UDP packet")
	}
	n := int(binary.BigEndian.Uint16(b[0:2]))
	if n+2 > len(b) {
		return nil, errors.New("teltonika: UDP length overruns the datagram")
	}
	b = b[:n+2]
	packetID := binary.BigEndian.Uint16(b[2:4])
	avlID := b[5]
	il := int(binary.BigEndian.Uint16(b[6:8]))
	if 8+il+3 > len(b) {
		return nil, errors.New("teltonika: UDP IMEI overruns the datagram")
	}
	imei := string(b[8 : 8+il])
	recs, err := c.records(b[8+il:])
	if err != nil {
		return nil, err
	}
	ack := binary.BigEndian.AppendUint16(nil, 5)
	ack = binary.BigEndian.AppendUint16(ack, packetID)
	ack = append(ack, 0x01, avlID, byte(len(recs)))
	return []*track.Message{{IMEI: imei, Records: recs, Reply: ack}}, nil
}

// ---- AVL data ---------------------------------------------------------------

type rd struct {
	b   []byte
	err error
}

func (r *rd) take(n int) []byte {
	if r.err != nil || len(r.b) < n {
		r.err = errors.New("teltonika: AVL data is truncated")
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

// records reads codec, count, records, count (the AVL data array).
func (c *codec) records(d []byte) ([]track.Record, error) {
	r := &rd{b: d}
	codecID := byte(r.u8())
	if codecID != Codec8 && codecID != Codec8E && codecID != Codec16 {
		return nil, fmt.Errorf("teltonika: codec 0x%02X is not an AVL codec", codecID)
	}
	ext := codecID == Codec8E
	n := int(r.u8())
	// IO IDs and counts: 1 byte in Codec 8, 2 in 8E; Codec 16 has 2-byte
	// IDs with 1-byte counts.
	idw, cntw := r.u8, r.u8
	switch codecID {
	case Codec8E:
		idw, cntw = r.u16, r.u16
	case Codec16:
		idw = r.u16
	}
	var out []track.Record
	for i := 0; i < n && r.err == nil; i++ {
		ts := int64(r.u64())
		prio := r.u8()
		lon := float64(int32(r.u32())) / 1e7
		lat := float64(int32(r.u32())) / 1e7
		alt := float64(int16(r.u16()))
		ang := float64(r.u16())
		sats := int(r.u8())
		spd := float64(r.u16())
		f := &track.Fix{Time: time.UnixMilli(ts).UTC(), Lat: lat, Lon: lon, Alt: &alt, Heading: &ang, Sats: &sats, Speed: &spd,
			Valid: sats > 0 && (lat != 0 || lon != 0)}
		event := uint16(idw())
		gen := -1
		if codecID == Codec16 {
			gen = int(r.u8()) // generation type
		}
		cntw() // total count
		ios := map[uint16]uint64{}
		raw := map[string]any{}
		for _, size := range []int{1, 2, 4, 8} {
			cnt := int(cntw())
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
				raw[strconv.Itoa(int(id))] = v
			}
		}
		if ext {
			cnt := int(r.u16())
			for j := 0; j < cnt && r.err == nil; j++ {
				id := r.u16()
				l := int(r.u16())
				raw[strconv.Itoa(int(id))] = fmt.Sprintf("%X", r.take(l))
			}
		}
		st := map[string]any{"io": raw, "priority": int(prio)}
		if gen >= 0 {
			st["generation"] = generationTypes[gen]
			if st["generation"] == "" {
				st["generation"] = strconv.Itoa(gen)
			}
		}
		for id, v := range ios {
			name, ok := c.cfg.io[id]
			if !ok {
				continue
			}
			def := knownIO[id]
			switch {
			case def.div < 0:
				st[name] = v != 0
			case def.div > 0:
				st[name] = float64(v) / def.div
			default:
				st[name] = v
			}
		}
		if h, ok := st["hdop"].(float64); ok {
			f.HDOP = &h
		}
		rec := track.Record{Fix: f, Status: st, Time: f.Time, Alerts: alerts(prio, event, ios)}
		out = append(out, rec)
	}
	if r.err != nil {
		return nil, r.err
	}
	if n2 := int(r.u8()); r.err != nil || n2 != n {
		return nil, errors.New("teltonika: record counts differ")
	}
	return out, nil
}

// generationTypes name Codec 16's record generation types.
var generationTypes = map[int]string{0: "on-exit", 1: "on-entrance", 2: "on-both", 3: "reserved", 4: "hysteresis",
	5: "on-change", 6: "eventual", 7: "periodical"}

func alerts(prio uint64, event uint16, ios map[uint16]uint64) []track.Alert {
	var out []track.Alert
	if prio == 2 {
		out = append(out, track.NewAlert("emergency", "priority-2"))
	}
	v, has := ios[event]
	code := "io-" + strconv.Itoa(int(event))
	switch event {
	case 253:
		switch v {
		case 1:
			out = append(out, track.NewAlert("harsh-acceleration", code))
		case 2:
			out = append(out, track.NewAlert("harsh-braking", code))
		case 3:
			out = append(out, track.NewAlert("rash-turning", code))
		}
	case 255:
		out = append(out, track.NewAlert("over-speed", code))
	case 252:
		if v == 1 {
			out = append(out, track.NewAlert("main-power-removed", code))
		} else if has {
			out = append(out, track.NewAlert("main-power-restored", code))
		}
	case 247:
		if v != 0 {
			out = append(out, track.NewAlert("impact", code))
		}
	case 246:
		if v != 0 {
			out = append(out, track.NewAlert("towing", code))
		}
	case 249, 318:
		if v != 0 {
			out = append(out, track.NewAlert("gnss-jamming", code))
		}
	case 239:
		if has && v != 0 {
			out = append(out, track.NewAlert("ignition-on", code))
		} else if has {
			out = append(out, track.NewAlert("ignition-off", code))
		}
	}
	return out
}
