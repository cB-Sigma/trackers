// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package calamp is CalAmp's LM Direct protocol of the LMU vehicle units
// over UDP: datagram decoding into track.Message, the acknowledgement the
// server owes, and user data commands correlated with the unit's
// acknowledgement. The codec is a track.DatagramCodec and a
// track.DatagramCommander; LM Direct has no stream framing here, so
// Decode (TCP) refuses.
//
// A datagram is an optional options header, then the message header and
// the message:
//
//	options   0x80|flags, then for each flag set a length byte and that
//	          many bytes: bit 0 mobile ID (BCD digits padded with F), bit 1
//	          mobile ID type, bit 2 authentication, bit 3 routing, bit 4
//	          forwarding, bit 5 response redirection
//	header    service type (0 unacknowledged, 1 acknowledged, 2 a response),
//	          message type, 2-byte sequence number
//
// The mobile ID becomes Message.IMEI ("" without an options header: the
// server then knows the unit by its address). A message with service
// type 1 is acknowledged with service 2, type 1, its sequence number, its
// type, ACK code 0, a spare byte and a 3-byte application version (zero):
// Message.Reply.
//
// Messages read:
//
//	2  event report    update time, fix time, latitude and longitude
//	                   (1e-7 degree), altitude (cm), speed (cm/s), heading,
//	                   satellites, fix status, carrier, RSSI (dBm), comm
//	                   state, HDOP, inputs, unit status, event index and
//	                   code, accumulators
//	8  locate report   the same without event index and code
//	10 mini event      update time, latitude, longitude, heading, speed
//	                   (km/h), satellites and fix flags in one byte, comm
//	                   state, inputs, event code, accumulators
//	4  user data       the event report's position fields, then route, ID,
//	                   length and the data (status userData)
//	1  ACK/NAK         the unit's answer to a command (Response; a non-zero
//	                   code fails it)
//	3  ID report       acknowledged, not decoded (Kind "id")
//	0  null            acknowledged (Kind "heartbeat")
//
// Other message types are acknowledged when asked and carry a warning.
// Inputs become ignition (bit 0) and din1..din7; accumulators acc0..accN
// (with accThreshold and accMask for accumulators of type 1). Event codes
// are defined by each unit's PEG script, so they are status values
// (event); profile.alerts maps codes to alert types. The fix status and
// HDOP are kept as reported (status fixStatus, hdop); a fix is valid when
// the fix status's invalid flag is clear. An options header whose
// extension bit (6) is set carries fields this codec does not read: the
// message is decoded as if it had none, with the warning optionsExtension.
//
// Commands. {"text": "…"} is sent to the unit as user data (type 4) with
// service type 1, so the unit acknowledges it; the codec is a
// track.Correlator and the unit's ACK with the command's sequence number
// completes it. {"hex": "…"} sends a whole LM Direct message as written
// (not correlated). The named commands have no LM Direct form this
// package can vouch for: a unit acts on user data only as its PEG script
// says, and the unit request (type 7) action codes are not in a document
// we could read. They fail with track.ErrUnsupported unless
// profile.namedCommands gives the user data text for the action.
//
// The profile (NewCodec; Profile):
//
//	alerts: {}         # event code → alert type, such as {"13": "emergency"}
//	namedCommands: {}  # action → user data text, with {imei} and {seconds}
package calamp

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/cB-Sigma/trackers/track"
)

// Message types.
const (
	TypeNull        = 0
	TypeAck         = 1
	TypeEventReport = 2
	TypeIDReport    = 3
	TypeUserData    = 4
	TypeLocate      = 8
	TypeMiniEvent   = 10
)

// Service types.
const (
	ServiceUnacknowledged = 0
	ServiceAcknowledged   = 1
	ServiceResponse       = 2
)

// NamedActions are the named commands framed by default: none.
var NamedActions = []string{}

// Interval bounds a profile's interval template, in seconds.
var Interval = track.IntervalRange{Min: 1, Max: 86400}

// Profile is the deployment's settings.
type Profile struct {
	// Alerts maps event codes (0 to 255, as the units' PEG scripts define
	// them) to alert types.
	Alerts map[string]string `json:"alerts,omitempty"`
	// NamedCommands gives the user data text of a named action, with
	// {imei} and {seconds}.
	NamedCommands track.NamedTemplates `json:"namedCommands,omitempty"`
}

type config struct {
	alerts map[int]string
	named  track.NamedTemplates
}

// NewCodec validates a profile (empty for the defaults) and returns a
// factory of codecs.
func NewCodec(raw json.RawMessage) (func() track.Codec, error) {
	var p Profile
	if err := track.StrictJSON(raw, &p); err != nil {
		return nil, err
	}
	if err := p.NamedCommands.Check(false); err != nil {
		return nil, err
	}
	cfg := &config{alerts: map[int]string{}, named: p.NamedCommands}
	for k, v := range p.Alerts {
		n, err := strconv.Atoi(k)
		if err != nil || n < 0 || n > 255 {
			return nil, fmt.Errorf("alerts: %q is not an event code 0 to 255", k)
		}
		if strings.TrimSpace(v) == "" {
			return nil, fmt.Errorf("alerts.%s: name the alert type", k)
		}
		cfg.alerts[n] = v
	}
	return func() track.Codec { return &codec{cfg: cfg} }, nil
}

type codec struct{ cfg *config }

// Decode refuses: LM Direct is read from datagrams (DecodeDatagram).
func (c *codec) Decode(*bufio.Reader) (*track.Message, error) {
	return nil, errors.New("calamp: LM Direct is a UDP protocol; take the units' datagrams on a UDP listener (DecodeDatagram)")
}

// DatagramCommands reports that commands can be sent in datagrams.
func (c *codec) DatagramCommands() bool { return true }

type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil || n < 0 || len(r.b) < n {
		r.err = errors.New("calamp: datagram truncated")
		return make([]byte, max(n, 0))
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}
func (r *reader) u8() uint8   { return r.take(1)[0] }
func (r *reader) u16() uint16 { return binary.BigEndian.Uint16(r.take(2)) }
func (r *reader) u32() uint32 { return binary.BigEndian.Uint32(r.take(4)) }
func (r *reader) i16() int16  { return int16(r.u16()) }
func (r *reader) i32() int32  { return int32(r.u32()) }

// DecodeDatagram reads one LM Direct datagram.
func (c *codec) DecodeDatagram(b []byte) ([]*track.Message, error) {
	r := &reader{b: b}
	m := &track.Message{}
	if len(b) > 0 && b[0]&0x80 != 0 {
		flags := r.u8()
		for bit := uint(0); bit < 6; bit++ {
			if flags>>bit&1 == 0 {
				continue
			}
			v := r.take(int(r.u8()))
			if bit == 0 {
				m.IMEI = strings.TrimRight(hex.EncodeToString(v), "f")
			}
		}
		if flags&0x40 != 0 {
			m.Warnings = append(m.Warnings, track.Warning{Code: "optionsExtension",
				Msg: "The datagram's options header has its extension bit set; the extension is not read, so the message may be misread."})
		}
	}
	service := r.u8()
	typ := r.u8()
	seq := r.u16()
	if r.err != nil {
		return nil, r.err
	}
	if service == ServiceAcknowledged {
		m.Reply = []byte{ServiceResponse, TypeAck, byte(seq >> 8), byte(seq), typ, 0, 0, 0, 0, 0}
	}
	switch typ {
	case TypeNull:
		m.Kind = "heartbeat"
	case TypeAck:
		acked := r.u8()
		code := r.u8()
		if r.err != nil {
			return nil, r.err
		}
		text := fmt.Sprintf("ACK type %d code %d", acked, code)
		if code != 0 {
			text = fmt.Sprintf("NAK type %d code %d", acked, code)
		}
		m.Kind = "response"
		m.Response = &text
		m.Failed = code != 0
		m.Correlation = fmt.Sprintf("%d/%04X", acked, seq)
		m.Details = map[string]any{"ackedType": int(acked), "ackCode": int(code)}
	case TypeIDReport:
		m.Kind = "id"
	case TypeEventReport, TypeLocate, TypeMiniEvent, TypeUserData:
		rec := c.position(r, typ)
		if r.err != nil {
			return nil, r.err
		}
		m.Records = []track.Record{rec}
		m.Kind = map[uint8]string{TypeEventReport: "event", TypeLocate: "locate", TypeMiniEvent: "event", TypeUserData: "userData"}[typ]
	default:
		m.Kind = "other"
		m.Warnings = append(m.Warnings, track.Warning{Code: "unknownMessage", Detail: strconv.Itoa(int(typ)),
			Msg: "An LM Direct message type this codec does not read was acknowledged and passed over."})
	}
	return []*track.Message{m}, nil
}

// position reads the fields of an event, locate, mini event or user data
// message.
func (c *codec) position(r *reader, typ uint8) track.Record {
	mini := typ == TypeMiniEvent
	st := map[string]any{}
	rec := track.Record{Status: st}
	updated := time.Unix(int64(r.u32()), 0).UTC()
	rec.Time = updated
	fix := &track.Fix{Time: updated}
	if !mini {
		fix.Time = time.Unix(int64(r.u32()), 0).UTC()
	}
	fix.Lat = float64(r.i32()) / 1e7
	fix.Lon = float64(r.i32()) / 1e7
	if !mini {
		fix.Alt = track.F(float64(r.i32()) / 100)
		fix.Speed = track.F(float64(r.u32()) * 0.036)
	}
	fix.Heading = track.F(float64(r.i16()))
	if mini {
		fix.Speed = track.F(float64(r.u8()))
		fs := r.u8()
		fix.Sats = track.I(int(fs & 0x0F))
		fix.Valid = fs&0x20 == 0
		st["fixStatus"] = int(fs >> 4)
	} else {
		fix.Sats = track.I(int(r.u8()))
		fs := r.u8()
		fix.Valid = fs&0x08 == 0
		st["fixStatus"] = int(fs)
		st["carrier"] = int(r.u16())
		st["rssi"] = int(r.i16())
	}
	st["commState"] = int(r.u8())
	if !mini {
		st["hdop"] = int(r.u8())
	}
	in := r.u8()
	st["ignition"] = in&1 == 1
	for i := 1; i < 8; i++ {
		st[fmt.Sprintf("din%d", i)] = in>>i&1 == 1
	}
	if !mini {
		st["unitStatus"] = int(r.u8())
	}
	if typ == TypeEventReport || mini {
		if !mini {
			st["eventIndex"] = int(r.u8())
		}
		code := int(r.u8())
		st["event"] = code
		if a, ok := c.cfg.alerts[code]; ok {
			rec.Alerts = append(rec.Alerts, track.NewAlert(a, strconv.Itoa(code)))
		}
	}
	if typ == TypeUserData {
		st["userDataRoute"] = int(r.u8())
		st["userDataId"] = int(r.u8())
		data := r.take(int(r.u16()))
		if utf8.Valid(data) {
			st["userData"] = string(data)
		} else {
			st["userData"] = hex.EncodeToString(data)
		}
	} else {
		accs := r.u8()
		if !mini {
			st["append"] = int(r.u8())
		}
		if accs>>6 == 1 {
			st["accThreshold"] = r.u32()
			st["accMask"] = r.u32()
		}
		for i := 0; i < int(accs&0x3F) && len(r.b) >= 4; i++ {
			st[fmt.Sprintf("acc%d", i)] = r.u32()
		}
	}
	if fix.Lat != 0 || fix.Lon != 0 {
		rec.Fix = fix
	}
	return rec
}

// Command frames a command: user data text, a whole message in hex, or a
// named command the profile gives a text for.
func (c *codec) Command(imei string, content any, seq uint32) ([]byte, bool, error) {
	if m, ok := content.(map[string]any); ok {
		if h, has := m["hex"]; has {
			s, _ := h.(string)
			b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
			if err != nil || len(b) < 4 {
				return nil, false, errors.New(`{"hex": …} is a whole LM Direct message in hexadecimal (service type, message type, sequence number, body)`)
			}
			return b, false, nil
		}
	}
	n, named, err := track.ReadNamed(content)
	if err != nil {
		return nil, false, err
	}
	var text string
	if named {
		if _, set := c.cfg.named[n.Action]; !set {
			return nil, false, track.Unsupported("calamp", n.Action,
				"an LMU acts on user data only as its PEG script says; set profile.namedCommands."+n.Action+" to the user data text your units' script acts on, or send the message as {\"hex\": …}")
		}
		if text, err = track.NamedText("calamp", n, c.cfg.named, nil, Interval, imei, ""); err != nil {
			return nil, false, err
		}
	} else if text, err = track.CommandText(content); err != nil {
		return nil, false, errors.New(`a command is {"text": "<user data>"}, {"hex": "<LM Direct message>"} or {"action": …}`)
	}
	if len(text) > 1000 {
		return nil, false, errors.New("calamp: user data is at most 1000 bytes")
	}
	s := uint16(seq)
	b := []byte{ServiceAcknowledged, TypeUserData, byte(s >> 8), byte(s), 0, 0}
	b = binary.BigEndian.AppendUint16(b, uint16(len(text)))
	return append(b, text...), true, nil
}

// Correlation: the unit's ACK carries the type and sequence number of the
// user data it acknowledges.
func (c *codec) Correlation(content any, seq uint32) (string, bool) {
	if m, ok := content.(map[string]any); ok {
		if _, has := m["hex"]; has {
			return "", false
		}
	}
	return fmt.Sprintf("%d/%04X", TypeUserData, uint16(seq)), true
}
