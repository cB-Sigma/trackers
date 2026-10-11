// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package eelink is the Eelink binary tracker protocol (terminal protocol
// 1.x and device protocol 2.0): package reading, decoding into
// track.Message, and command framing. Our own implementation from
// Eelink's "Terminal Communication Protocol Second Edition V1.8.4" and
// "EELINK Device Protocol V2.0" (2017); facts cross-checked against
// Traccar's decoder tests.
//
// A package is 0x67 0x67, the package identifier (PID), a 16-bit size
// (sequence and content), a 16-bit sequence and the content. Answers
// repeat PID and sequence. Read:
//
//	0x01 login (IMEI as BCD, language; 2.0 adds time zone, versions):
//	     answered empty (1.x) or with server time, protocol version 1 and
//	     no param-set action (2.0, told apart by its length)
//	0x03 heartbeat (status word), answered
//	0x02 GPS, 0x04 alarm, 0x05 state, 0x06 SMS (1.x): time, position in
//	     1/500", speed, course, cell, fix flag; 0x02 is not answered
//	0x12 location, 0x14 warning, 0x15 report, 0x16 message (2.0): time
//	     and a mask of GPS, three cells and three WiFi access points (bit
//	     7: an LTE cell and WiFi list, as Traccar reads it), the status
//	     word, and on 0x12 battery, analogue inputs, mileage, steps and
//	     sensors. 0x12 is answered only over UDP or with ackLocation
//	0x07 OBD (1.x): its PID values, raw
//	0x80 the device's answer to an instruction (UID, result text; a WHERE
//	     answer also becomes a position)
//
// Other packages (2.0 OBD, pedometer, param-set) are answered and passed
// over with a warning. Over UDP each datagram has an "EL" (or "EP")
// header with size, a rotate-and-add 16-bit checksum and the IMEI; the
// codec is a track.DatagramCodec and, once it has read a datagram, frames
// its answers and commands with that header (track.DatagramCommander).
//
// Commands are instruction packages 0x80 of type 1 with the sequence as
// UID and the command text ("WHERE#"); the device answers with the same
// UID, so the codec is a track.Correlator (a zero UID names no command).
//
// The profile (NewCodec; Profile):
//
//	ackLocation: false        # also answer 0x12 locations over TCP
//	alarms: {"0x05": towing}  # extra or replaced warning/alarm codes → alert type
//	failureWords: [error, fail]   # default; an answer holding one fails the command
//	namedCommands: {interval: "COLLECT,{seconds}#"}   # replaces a named command's text
//
// Named commands (track.Named): engineStop "RELAY,1#", engineResume
// "RELAY,0#", locate "WHERE#", reboot "RESET#", interval
// "COLLECT,<seconds>,0,0,0,1#" (time strategy only: it also turns the
// distance and turn strategies off; 1 to 86400 s).
package eelink

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

	"github.com/cB-Sigma/trackers/track"
)

// Package identifiers.
const (
	PLogin       = 0x01
	PGPS         = 0x02
	PHeartbeat   = 0x03
	PAlarm       = 0x04
	PState       = 0x05
	PSMS         = 0x06
	POBD         = 0x07
	PLocation    = 0x12
	PWarning     = 0x14
	PReport      = 0x15
	PMessage     = 0x16
	PInstruction = 0x80
	PBroadcast   = 0x81
)

// Profile is the manufacturer-variation settings.
type Profile struct {
	AckLocation   bool                 `json:"ackLocation,omitempty"`
	Alarms        map[string]string    `json:"alarms,omitempty"`
	FailureWords  []string             `json:"failureWords,omitempty"`
	NamedCommands track.NamedTemplates `json:"namedCommands,omitempty"`
}

type config struct {
	ackLoc bool
	alarms map[byte]track.Alert
	fail   []string
	named  track.NamedTemplates
}

// NewCodec validates a profile (empty for the defaults) and returns a
// factory of codecs, one per connection.
func NewCodec(raw json.RawMessage) (func() track.Codec, error) {
	var p Profile
	if err := track.StrictJSON(raw, &p); err != nil {
		return nil, err
	}
	c := config{ackLoc: p.AckLocation, alarms: map[byte]track.Alert{}, named: p.NamedCommands}
	fw, err := track.FailureWords(p.FailureWords, "error", "fail")
	if err != nil {
		return nil, err
	}
	c.fail = fw
	if err := p.NamedCommands.Check(false); err != nil {
		return nil, err
	}
	for k, v := range defaultAlarms {
		c.alarms[k] = track.NewAlert(v, fmt.Sprintf("0x%02X", k))
	}
	for k, v := range p.Alarms {
		n, err := strconv.ParseUint(k, 0, 8)
		if err != nil || v == "" {
			return nil, fmt.Errorf("alarms: %q must map a code such as \"0x05\" to an alert type", k)
		}
		c.alarms[byte(n)] = track.NewAlert(v, fmt.Sprintf("0x%02X", n))
	}
	return func() track.Codec { return &codec{cfg: c} }, nil
}

// defaultAlarms are the warning (2.0) and alarm (1.x) types; 0x25 is
// read as Traccar reads it (not in the documents).
var defaultAlarms = map[byte]string{
	0x01: "main-power-removed", 0x02: "emergency", 0x03: "low-battery", 0x04: "vibration",
	0x05: "displacement", 0x08: "gnss-antenna-cut", 0x09: "gnss-antenna-short",
	0x20: "temperature-range", 0x21: "humidity-range", 0x22: "illuminance-range", 0x23: "co2-range",
	0x25: "tamper",
	0x81: "low-speed", 0x82: "over-speed", 0x83: "geofence-enter", 0x84: "geofence-exit", 0x85: "impact", 0x86: "fall",
}

type codec struct {
	cfg  config
	imei string
	// udp is set once a datagram was read: answers and commands then
	// carry the UDP header with this mark.
	udp  bool
	mark string
}

// Package is one decoded package.
type Package struct {
	PID     byte
	Seq     uint16
	Content []byte
}

// Encode builds a package.
func Encode(pid byte, seq uint16, content []byte) []byte {
	b := []byte{0x67, 0x67, pid}
	b = binary.BigEndian.AppendUint16(b, uint16(2+len(content)))
	b = binary.BigEndian.AppendUint16(b, seq)
	return append(b, content...)
}

// ReadPackage reads one package, skipping bytes until 0x67 0x67.
func ReadPackage(r *bufio.Reader) (*Package, error) {
	for {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if b != 0x67 {
			continue
		}
		nb, err := r.Peek(1)
		if err != nil {
			return nil, err
		}
		if nb[0] != 0x67 {
			continue
		}
		_, _ = r.ReadByte()
		var h [3]byte
		if _, err := io.ReadFull(r, h[:]); err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(h[1:3]))
		if n < 2 {
			return nil, fmt.Errorf("eelink: size %d is too short", n)
		}
		body := make([]byte, n)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, err
		}
		return &Package{PID: h[0], Seq: binary.BigEndian.Uint16(body), Content: body[2:]}, nil
	}
}

// Sum16 is the datagram checksum: rotate left by one, then add each byte.
func Sum16(b []byte) uint16 {
	var s uint16
	for _, v := range b {
		s = (s<<1 | s>>15) + uint16(v)
	}
	return s
}

// Datagram wraps packages in the UDP header: mark ("EL"), size, checksum
// and the IMEI as BCD.
func Datagram(mark, imei string, packages []byte) []byte {
	id := imeiBytes(imei)
	body := append(id, packages...)
	b := append([]byte(mark[:2]), 0, 0, 0, 0)
	binary.BigEndian.PutUint16(b[2:], uint16(2+len(body)))
	binary.BigEndian.PutUint16(b[4:], Sum16(body))
	return append(b, body...)
}

func imeiBytes(imei string) []byte {
	s := imei
	for len(s) < 16 {
		s = "0" + s
	}
	var out [8]byte
	for i := 0; i < 16 && i/2 < 8; i++ {
		d := byte(0)
		if s[i] >= '0' && s[i] <= '9' {
			d = s[i] - '0'
		}
		if i%2 == 0 {
			out[i/2] = d << 4
		} else {
			out[i/2] |= d
		}
	}
	return out[:]
}

func readIMEI(b []byte) string {
	s := strings.TrimLeft(fmt.Sprintf("%X", b), "0")
	for len(s) < 15 {
		s = "0" + s
	}
	return s
}

func (c *codec) Decode(r *bufio.Reader) (*track.Message, error) {
	p, err := ReadPackage(r)
	if err != nil {
		return nil, err
	}
	return c.message(p)
}

// DecodeDatagram reads a UDP datagram: header, then its packages.
func (c *codec) DecodeDatagram(b []byte) ([]*track.Message, error) {
	if len(b) < 14 || b[0] != 'E' || (b[1] != 'L' && b[1] != 'P') {
		return nil, errors.New("eelink: a datagram starts with EL or EP")
	}
	n := int(binary.BigEndian.Uint16(b[2:4]))
	if n < 10 || 4+n > len(b) {
		return nil, fmt.Errorf("eelink: datagram size %d for %d bytes", n, len(b))
	}
	body := b[6 : 4+n]
	if Sum16(body) != binary.BigEndian.Uint16(b[4:6]) {
		return nil, errors.New("eelink: datagram checksum mismatch")
	}
	c.udp, c.mark = true, string(b[:2])
	c.imei = readIMEI(body[:8])
	r := bufio.NewReader(strings.NewReader(string(body[8:])))
	var out []*track.Message
	for {
		p, err := ReadPackage(r)
		if errors.Is(err, io.EOF) {
			return out, nil
		}
		if err != nil {
			return out, err
		}
		m, err := c.message(p)
		var sk *track.Skip
		if errors.As(err, &sk) {
			out = append(out, &track.Message{IMEI: c.imei, Reply: sk.Reply, Warnings: []track.Warning{sk.Warning}})
			continue
		}
		if err != nil {
			continue
		}
		if m.IMEI == "" {
			m.IMEI = c.imei
		}
		out = append(out, m)
	}
}

// DatagramCommands: commands are framed in the UDP header once the codec
// has read a datagram.
func (c *codec) DatagramCommands() bool { return true }

func (c *codec) wrap(b []byte) []byte {
	if !c.udp || b == nil {
		return b
	}
	return Datagram(c.mark, c.imei, b)
}

func short(pid byte, n int) error {
	return &track.Skip{Warning: track.Warning{Code: "shortPacket", Detail: fmt.Sprintf("0x%02X, %d bytes", pid, n),
		Msg: "A package shorter than its identifier needs was passed over (the connection stays up)."}}
}

func (c *codec) message(p *Package) (*track.Message, error) {
	m := &track.Message{IMEI: c.imei}
	ack := func(content []byte) { m.Reply = c.wrap(Encode(p.PID, p.Seq, content)) }
	b := p.Content
	switch p.PID {
	case PLogin:
		if len(b) < 8 {
			return nil, short(p.PID, len(b))
		}
		m.Login = true
		c.imei = readIMEI(b[:8])
		m.IMEI, m.Kind = c.imei, "login"
		st := map[string]any{}
		if len(b) >= 9 {
			st["language"] = map[byte]string{0: "zh", 1: "en"}[b[8]]
		}
		if len(b) >= 14 {
			st["timezoneMinutes"] = int(int8(b[9])) * 15
			st["systemVersion"] = version(b[10:12])
			st["appVersion"] = version(b[12:14])
			reply := binary.BigEndian.AppendUint32(nil, uint32(time.Now().Unix()))
			ack(append(reply, 0x00, 0x01, 0x00))
		} else {
			ack(nil)
		}
		m.Records = []track.Record{{Status: st, Time: time.Now().UTC()}}
	case PHeartbeat:
		if len(b) < 2 {
			return nil, short(p.PID, len(b))
		}
		m.Kind = "heartbeat"
		m.Records = []track.Record{{Status: statusWord(binary.BigEndian.Uint16(b), false), Time: time.Now().UTC()}}
		ack(nil)
	case PGPS, PAlarm, PState, PSMS:
		if len(b) < 25 {
			return nil, short(p.PID, len(b))
		}
		rec := oldPosition(b)
		rest := b[25:]
		switch p.PID {
		case PGPS:
			m.Kind = "location"
			if len(rest) >= 2 {
				for k, v := range statusWord(binary.BigEndian.Uint16(rest), false) {
					rec.Status[k] = v
				}
				rest = rest[2:]
			}
			if len(rest) >= 8 {
				rec.Status["batteryVoltage"] = float64(binary.BigEndian.Uint16(rest)) / 1000
				rec.Status["gsm"] = int(binary.BigEndian.Uint16(rest[2:]))
				rec.Status["adc1"] = int(binary.BigEndian.Uint16(rest[4:]))
				rec.Status["adc2"] = int(binary.BigEndian.Uint16(rest[6:]))
			}
			if c.udp || c.cfg.ackLoc {
				ack(nil)
			}
		case PAlarm:
			m.Kind = "alarm"
			if len(rest) >= 1 {
				rec.Alerts = append(rec.Alerts, c.alert(rest[0]))
			}
			ack(nil)
		case PState:
			m.Kind = "state"
			if len(rest) >= 1 {
				rec.Status["event"] = int(rest[0])
				switch rest[0] {
				case 1:
					rec.Status["ignition"] = true
					rec.Alerts = append(rec.Alerts, track.NewAlert("ignition-on", "state-0x01"))
				case 2:
					rec.Status["ignition"] = false
					rec.Alerts = append(rec.Alerts, track.NewAlert("ignition-off", "state-0x02"))
				}
				if len(rest) >= 7 && rest[0] <= 3 {
					for k, v := range statusWord(binary.BigEndian.Uint16(rest[5:]), false) {
						if _, set := rec.Status[k]; !set {
							rec.Status[k] = v
						}
					}
				}
			}
			ack(nil)
		case PSMS:
			m.Kind = "sms"
			if len(rest) >= 21 {
				rec.Status["smsFrom"] = cstr(rest[:21])
				rec.Status["smsText"] = string(rest[21:])
				ack(rest[:21])
			} else {
				ack(nil)
			}
		}
		m.Records = []track.Record{rec}
	case POBD:
		m.Kind = "obd"
		if len(b) == 4 {
			m.Records = []track.Record{{Status: statusWord(binary.BigEndian.Uint16(b), false), Time: time.Now().UTC()}}
		} else if len(b) >= 4 {
			obd := map[string]any{}
			for rest := b[4:]; len(rest) >= 5; rest = rest[5:] {
				obd[fmt.Sprintf("0x%02X", rest[0])] = int(int32(binary.BigEndian.Uint32(rest[1:])))
			}
			t := time.Unix(int64(binary.BigEndian.Uint32(b)), 0).UTC()
			m.Records = []track.Record{{Status: map[string]any{"obd": obd}, Time: t}}
		}
		ack(nil)
	case PLocation, PWarning, PReport, PMessage:
		rec, rest, err := newPosition(b)
		if err != nil {
			return nil, short(p.PID, len(b))
		}
		switch p.PID {
		case PLocation:
			m.Kind = "location"
			if c.udp || c.cfg.ackLoc {
				ack(nil)
			}
		case PWarning:
			m.Kind = "warning"
			if len(rest) >= 1 {
				rec.Alerts = append(rec.Alerts, c.alert(rest[0]))
				rest = rest[1:]
			}
			ack(nil)
		case PReport:
			m.Kind = "report"
			if len(rest) >= 1 {
				rec.Status["event"] = int(rest[0])
				switch rest[0] {
				case 1:
					rec.Alerts = append(rec.Alerts, track.NewAlert("ignition-on", "report-0x01"))
				case 2:
					rec.Alerts = append(rec.Alerts, track.NewAlert("ignition-off", "report-0x02"))
				case 3:
					rec.Status["inputChanged"] = true
				}
				rest = rest[1:]
			}
			ack(nil)
		case PMessage:
			m.Kind = "message"
			if len(rest) >= 21 {
				rec.Status["smsFrom"] = cstr(rest[:21])
				rec.Status["smsText"] = string(rest[21:])
				ack(rest[:21])
			} else {
				ack(nil)
			}
			rest = nil
		}
		if len(rest) >= 2 {
			sw := binary.BigEndian.Uint16(rest)
			if rec.Fix != nil {
				rec.Fix.Valid = sw&1 != 0
			}
			for k, v := range statusWord(sw, true) {
				if _, set := rec.Status[k]; !set {
					rec.Status[k] = v
				}
			}
			if p.PID == PReport {
				switch rec.Status["event"] {
				case 1:
					rec.Status["ignition"] = true
				case 2:
					rec.Status["ignition"] = false
				}
			}
			rest = rest[2:]
		}
		if p.PID == PLocation {
			locationExtras(rest, rec.Status)
		}
		m.Records = []track.Record{rec}
	case PInstruction:
		if len(b) < 5 {
			return nil, short(p.PID, len(b))
		}
		text := string(b[5:])
		m.Kind = "response"
		m.Response, m.Failed = &text, track.AnswerFailed(text, c.cfg.fail)
		m.Correlation = uidCorrelation(binary.BigEndian.Uint32(b[1:5]))
		if f := whereFix(text); f != nil {
			m.Records = []track.Record{{Fix: f, Time: f.Time}}
		}
	case PBroadcast:
		return nil, track.ErrSkip
	default:
		r := Encode(p.PID, p.Seq, nil)
		return nil, &track.Skip{Reply: c.wrap(r), Warning: track.Warning{Code: "unknownPacket", Detail: fmt.Sprintf("0x%02X", p.PID),
			Msg: "A package this codec does not read was answered and passed over."}}
	}
	return m, nil
}

func version(b []byte) string {
	v := binary.BigEndian.Uint16(b)
	return fmt.Sprintf("%d.%d.%d", v>>8, v>>4&0x0F, v&0x0F)
}

func cstr(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

func (c *codec) alert(code byte) track.Alert {
	if a, ok := c.cfg.alarms[code]; ok {
		return a
	}
	return track.Alert{Type: fmt.Sprintf("alarm-0x%02X", code), Severity: track.Minor, Code: fmt.Sprintf("0x%02X", code)}
}

// statusWord reads the 16-bit device status: each feature has a "has"
// bit and a value bit. With v2, bit 9 is motion and bit 10 GPS running.
func statusWord(s uint16, v2 bool) map[string]any {
	bit := func(n uint) bool { return s&(1<<n) != 0 }
	st := map[string]any{"statusWord": int(s)}
	if bit(1) {
		st["ignition"] = bit(2)
	}
	if bit(3) {
		st["armed"] = bit(4)
		if v2 {
			st["movement"] = bit(9)
		}
	}
	if bit(5) {
		st["fuelCut"] = bit(6)
	}
	if bit(7) {
		st["charging"] = bit(8)
	}
	if v2 {
		st["gpsRunning"] = bit(10)
	}
	return st
}

// oldPosition reads the 1.x position: time, latitude, longitude, speed,
// course, MCC, MNC, LAC, 24-bit cell ID, fix flag.
func oldPosition(b []byte) track.Record {
	t := time.Unix(int64(binary.BigEndian.Uint32(b)), 0).UTC()
	spd := float64(b[12])
	hdg := float64(binary.BigEndian.Uint16(b[13:]))
	f := &track.Fix{Time: t, Lat: float64(int32(binary.BigEndian.Uint32(b[4:]))) / 1800000,
		Lon: float64(int32(binary.BigEndian.Uint32(b[8:]))) / 1800000, Speed: &spd, Heading: &hdg, Valid: b[24]&1 != 0}
	cell := track.Cell{MCC: int(binary.BigEndian.Uint16(b[15:])), MNC: int(binary.BigEndian.Uint16(b[17:])),
		LAC: int(binary.BigEndian.Uint16(b[19:])), CID: int64(b[21])<<16 | int64(b[22])<<8 | int64(b[23])}
	rec := track.Record{Fix: f, Time: t, Status: map[string]any{}}
	if cell.MCC != 0 || cell.CID != 0 {
		rec.Network = &track.Network{Cells: []track.Cell{cell}}
	}
	return rec
}

type reader struct {
	b   []byte
	err bool
}

func (r *reader) take(n int) []byte {
	if r.err || len(r.b) < n {
		r.err = true
		return make([]byte, n)
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}
func (r *reader) u8() int  { return int(r.take(1)[0]) }
func (r *reader) u16() int { return int(binary.BigEndian.Uint16(r.take(2))) }
func (r *reader) u32() uint32 {
	return binary.BigEndian.Uint32(r.take(4))
}

func mac(b []byte) string {
	p := make([]string, len(b))
	for i, x := range b {
		p[i] = fmt.Sprintf("%02x", x)
	}
	return strings.Join(p, ":")
}

// newPosition reads the 2.0 position (time, mask and the parts the mask
// names) and returns what follows it.
func newPosition(b []byte) (track.Record, []byte, error) {
	r := &reader{b: b}
	t := time.Unix(int64(r.u32()), 0).UTC()
	mask := r.u8()
	rec := track.Record{Time: t, Status: map[string]any{}}
	if mask&0x01 != 0 {
		lat := float64(int32(r.u32())) / 1800000
		lon := float64(int32(r.u32())) / 1800000
		alt := float64(int16(r.u16()))
		spd := float64(r.u16())
		hdg := float64(r.u16())
		sats := r.u8()
		rec.Fix = &track.Fix{Time: t, Lat: lat, Lon: lon, Alt: &alt, Speed: &spd, Heading: &hdg, Sats: &sats, Valid: true}
	}
	nw := &track.Network{}
	var mcc, mnc int
	cell := func() {
		lac := r.u16()
		cid := int64(r.u32())
		rssi := r.u8() - 110
		nw.Cells = append(nw.Cells, track.Cell{MCC: mcc, MNC: mnc, LAC: lac, CID: cid, RSSI: &rssi})
	}
	if mask&0x02 != 0 {
		mcc, mnc = r.u16(), r.u16()
		cell()
	}
	for _, bit := range []int{0x04, 0x08} {
		if mask&bit != 0 {
			cell()
		}
	}
	for _, bit := range []int{0x10, 0x20, 0x40} {
		if mask&bit != 0 {
			m := mac(r.take(6))
			rssi := int(int8(r.u8()))
			nw.WiFi = append(nw.WiFi, track.WiFiAP{MAC: m, RSSI: &rssi})
		}
	}
	if mask&0x80 != 0 {
		r.u8() // radio access technology
		count := r.u8()
		if cells := count & 0x07; cells > 0 {
			mcc, mnc = r.u16(), r.u16()
			lac := r.u16()
			r.u16() // tracking area code
			cid := int64(r.u32())
			r.take(6) // timing advance, physical cell ID, EARFCN
			rssi := int(int8(r.u8()))
			nw.Cells = append(nw.Cells, track.Cell{MCC: mcc, MNC: mnc, LAC: lac, CID: cid, RSSI: &rssi})
			r.take((cells - 1) * 5)
		}
		for i := 0; i < count>>3&0x0F; i++ {
			m := mac(r.take(6))
			rssi := int(int8(r.u8()))
			nw.WiFi = append(nw.WiFi, track.WiFiAP{MAC: m, RSSI: &rssi})
		}
	}
	if r.err {
		return rec, nil, errors.New("short position")
	}
	if len(nw.Cells) > 0 || len(nw.WiFi) > 0 {
		rec.Network = nw
	}
	return rec, r.b, nil
}

// locationExtras reads the fields after a 0x12 location's status word;
// zero means "not present" for the sensors.
func locationExtras(b []byte, st map[string]any) {
	r := &reader{b: b}
	if len(r.b) >= 2 {
		st["batteryVoltage"] = float64(r.u16()) / 1000
	}
	if len(r.b) >= 4 {
		st["adc0"], st["adc1"] = r.u16(), r.u16()
	}
	if len(r.b) >= 4 {
		st["odometer"] = int(r.u32())
	}
	if len(r.b) >= 4 {
		r.take(4) // GSM and GPS counters
	}
	if len(r.b) >= 4 {
		if steps := r.u16(); steps > 0 {
			st["steps"] = steps
		}
		r.u16() // walking time
	}
	if len(r.b) >= 12 {
		if v := r.u16(); v != 0 {
			st["temperature"] = float64(int16(v)) / 256
		}
		if v := r.u16(); v != 0 {
			st["humidity"] = float64(v) / 10
		}
		if v := r.u32(); v != 0 {
			st["illuminance"] = float64(v) / 256
		}
		if v := r.u32(); v != 0 {
			st["co2"] = int(v)
		}
	}
}

// whereFix reads a WHERE answer: Lat:N22.5,Lon:E113.9,Course:..,Speed:..km/h,DateTime:2017-12-02 11:29:43
// (fields separated by commas or line breaks).
func whereFix(s string) *track.Fix {
	vals := map[string]string{}
	for _, part := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == '\r' }) {
		k, v, ok := strings.Cut(part, ":")
		if ok {
			vals[strings.ReplaceAll(strings.ToLower(strings.TrimSpace(k)), " ", "")] = strings.TrimSpace(v)
		}
	}
	coord := func(v string, neg byte) (float64, bool) {
		if len(v) < 2 {
			return 0, false
		}
		x, err := strconv.ParseFloat(v[1:], 64)
		if err != nil {
			return 0, false
		}
		if v[0] == neg {
			x = -x
		}
		return x, true
	}
	lat, ok1 := coord(vals["lat"], 'S')
	lon, ok2 := coord(vals["lon"], 'W')
	t, err := time.Parse("2006-01-02 15:04:05", vals["datetime"])
	if !ok1 || !ok2 || err != nil {
		return nil
	}
	f := &track.Fix{Time: t, Lat: lat, Lon: lon, Valid: true}
	if v, err := strconv.ParseFloat(vals["course"], 64); err == nil {
		f.Heading = &v
	}
	sp := strings.TrimRight(strings.ToLower(vals["speed"]), "km/h")
	if v, err := strconv.ParseFloat(sp, 64); err == nil {
		f.Speed = &v
	}
	return f
}

func uidCorrelation(uid uint32) string {
	if uid == 0 {
		return ""
	}
	return strconv.FormatUint(uint64(uid), 10)
}
