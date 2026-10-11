// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package atrack is the ATrack (AK, AX, AT, AU and AY series) tracker
// protocol: frame reading, decoding into track.Message, and command
// framing. Our own implementation from ATrack's protocol document
// (revision 1.3.6); facts cross-checked against Traccar's decoder tests.
//
// A device sends position packets in one of two forms, chosen with its
// AT$FORM command, each starting with a two-character prefix ("@P" by
// default; any two bytes but 0x0D0A, 0xFE02 and 0x00):
//
//	binary:  prefix, CRC (2), length (2), sequence (2), unit ID (8), records
//	ASCII:   prefix,CRC,length,sequence,unit ID,record CR LF [record CR LF …]
//
// The CRC is CRC-16/ARC: over length..end in binary, and from the comma
// before the length to the end in ASCII. The length counts from the
// sequence (binary) or the comma after the length (ASCII) to the end. A
// binary packet with a bad CRC is dropped; an ASCII one is read with a
// warning, since some firmware's ASCII CRC does not follow that rule. The
// unit ID is the IMEI unless set otherwise with AT$UNID. A record holds GPS,
// RTC and sending times (Unix seconds, or year..second when AT$FORM's
// time format is 1: told apart by the year), longitude and latitude in
// millionths of a degree, heading, report ID, odometer (0.1 km), HDOP
// (0.1), inputs, speed (km/h), outputs, analogue input (mV), driver ID,
// two temperatures (0.1 °C; 2000 when no sensor), a text message, and the
// custom fields AT$FORM appends. When those start with %CI the record names
// its own layout; otherwise set profile.form to the device's.
//
// Every position packet and keep-alive (0xFE02, unit ID, sequence) is
// answered with 0xFE02, the unit ID and the sequence. The first packet of
// a connection is its Login (the protocol has no login of its own).
//
// Commands are text lines "AT$<command>[+tag]=[password,]<parameters>"
// ending CR LF. Answers are "$OK", "$ERROR=<code>" or, to a query,
// "$<command>=<values>", each repeating the tag. Command adds the
// sequence as tag (at most five digits) and the codec is a
// track.Correlator, so an answer completes the command whose tag it
// repeats (an untagged answer, from firmware that drops tags, is taken
// too). AT$GPOS is answered with a position report, not text, so it
// expects no answer.
//
// The profile (NewCodec; Profile):
//
//	checkCrc: true            # default true; false accepts packets with a bad CRC
//	form: "%MV%BV%SA"         # the AT$FORM custom fields, when records do not carry %CI
//	alarms: {"101": emergency}   # report ID → alert type (user reports 101..164 mean what AT$REPT made them)
//	commandTag: true          # default true; false sends commands without a tag
//	commandPassword: "1234"   # AT$PASS password, put before the parameters of named commands
//	namedCommands: {engineStop: "AT$OUTC=2,1"}   # replaces a named command's text
//
// Named commands (track.Named): engineStop "AT$OUTC=1,1" and engineResume
// "AT$OUTC=1,0" (digital output 1 on and off: wire the relay there or
// change the output), locate "AT$GPOS", reboot "AT$REST=1,0", interval
// "AT$TRAC=1,<seconds>" (time mode, 1 to 65535 s).
package atrack

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/cB-Sigma/trackers/track"
)

// Profile is the manufacturer-variation settings.
type Profile struct {
	// CheckCRC (default true) drops packets whose CRC does not match.
	CheckCRC *bool `json:"checkCrc,omitempty"`
	// Form is the device's AT$FORM custom-information string ("%MV%BV"),
	// for records that do not carry it themselves (no %CI).
	Form string `json:"form,omitempty"`
	// Alarms maps report IDs to alert types.
	Alarms map[string]string `json:"alarms,omitempty"`
	// CommandTag (default true) tags each command with its sequence.
	CommandTag *bool `json:"commandTag,omitempty"`
	// CommandPassword is the AT$PASS password for named commands.
	CommandPassword string `json:"commandPassword,omitempty"`
	// NamedCommands replaces the text of a named command; placeholders
	// {seconds}, {password} and {imei}; "" turns one off.
	NamedCommands track.NamedTemplates `json:"namedCommands,omitempty"`
}

type config struct {
	crc    bool
	form   []string
	alarms map[int]track.Alert
	tag    bool
	pass   string
	named  track.NamedTemplates
}

// NewCodec validates a profile (empty for the defaults) and returns a
// factory of codecs, one per connection.
func NewCodec(raw json.RawMessage) (func() track.Codec, error) {
	var p Profile
	if err := track.StrictJSON(raw, &p); err != nil {
		return nil, err
	}
	c := config{crc: p.CheckCRC == nil || *p.CheckCRC, tag: p.CommandTag == nil || *p.CommandTag,
		pass: p.CommandPassword, named: p.NamedCommands, alarms: map[int]track.Alert{}}
	if p.Form != "" {
		f, err := parseForm(p.Form)
		if err != nil {
			return nil, fmt.Errorf("form: %w", err)
		}
		c.form = f
	}
	if strings.ContainsAny(p.CommandPassword, ",\r\n") {
		return nil, errors.New("commandPassword: must not contain a comma or line break")
	}
	if err := p.NamedCommands.Check(true); err != nil {
		return nil, err
	}
	for k, v := range defaultAlarms {
		c.alarms[k] = track.NewAlert(v, strconv.Itoa(k))
	}
	for k, v := range p.Alarms {
		n, err := strconv.Atoi(k)
		if err != nil || n < 0 || n > 255 || v == "" {
			return nil, fmt.Errorf("alarms: %q must map a report ID (0 to 255) to an alert type", k)
		}
		c.alarms[n] = track.NewAlert(v, k)
	}
	return func() track.Codec { return &codec{cfg: c} }, nil
}

// defaultAlarms are the fixed report IDs that are alerts.
var defaultAlarms = map[int]string{13: "gsm-jamming", 14: "impact"}

// parseForm splits "%CI%MV%BV" into its field codes.
func parseForm(s string) ([]string, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "%") {
		return nil, fmt.Errorf("%q: the custom fields are codes each starting with %%, such as %%MV%%BV", s)
	}
	parts := strings.Split(s[1:], "%")
	for _, k := range parts {
		if k == "" {
			return nil, fmt.Errorf("%q has an empty field code", s)
		}
		for i := 0; i < len(k); i++ {
			if !(k[i] >= 'A' && k[i] <= 'Z' || k[i] >= '0' && k[i] <= '9') {
				return nil, fmt.Errorf("%q: field code %q is not upper-case letters and digits", s, k)
			}
		}
	}
	return parts, nil
}

type codec struct {
	cfg  config
	imei string
}

// ErrCRC is a packet whose CRC does not match.
var ErrCRC = errors.New("atrack: CRC mismatch")

const maxLen = 1 << 16

// Ack is the server's answer to a position packet or keep-alive: 0xFE02,
// the unit ID and the sequence (the device's keep-alive has the same form).
func Ack(unit uint64, seq uint16) []byte {
	b := []byte{0xFE, 0x02}
	b = binary.BigEndian.AppendUint64(b, unit)
	return binary.BigEndian.AppendUint16(b, seq)
}

// BinaryFrame frames binary records: prefix (two characters), CRC, length,
// sequence, unit ID and the records as they are.
func BinaryFrame(prefix string, seq uint16, unit uint64, records []byte) []byte {
	body := binary.BigEndian.AppendUint16(nil, seq)
	body = binary.BigEndian.AppendUint64(body, unit)
	body = append(body, records...)
	withLen := binary.BigEndian.AppendUint16(nil, uint16(len(body)))
	withLen = append(withLen, body...)
	b := append([]byte(prefix[:2]), 0, 0)
	binary.BigEndian.PutUint16(b[2:], track.CRC16IBM(withLen))
	return append(b, withLen...)
}

// ASCIIFrame frames an ASCII packet: body is "<sequence>,<unit ID>,<record>\r\n…";
// the result is "<prefix>,<CRC>,<length>,<body>".
func ASCIIFrame(prefix, body string) string {
	l := len(body) + 1
	tail := fmt.Sprintf(",%d,%s", l, body)
	return fmt.Sprintf("%s,%04X%s", prefix[:2], track.CRC16IBM([]byte(tail)), tail)
}

func (c *codec) Decode(r *bufio.Reader) (*track.Message, error) {
	for {
		h, err := r.Peek(1)
		if err != nil {
			return nil, err
		}
		switch h[0] {
		case '\r', '\n', 0:
			// Line ends and padding between packets.
			_, _ = r.Discard(1)
			continue
		case '$':
			return c.answer(r)
		}
		h, err = r.Peek(3)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
		switch {
		case h[0] == 0xFE && h[1] == 0x02:
			return c.keepAlive(r)
		case h[2] == ',' && asciiHeader(r):
			return c.ascii(r)
		}
		return c.binary(r)
	}
}

// asciiHeader tells an ASCII packet ("@P,1A2B,") from a binary one whose
// CRC happens to start with a comma: the CRC field is four hexadecimal
// digits and a comma.
func asciiHeader(r *bufio.Reader) bool {
	h, err := r.Peek(8)
	if err != nil {
		return false
	}
	for _, x := range h[3:7] {
		if !(x >= '0' && x <= '9' || x >= 'A' && x <= 'F' || x >= 'a' && x <= 'f') {
			return false
		}
	}
	return h[7] == ','
}

func (c *codec) login(m *track.Message, unit uint64) {
	m.IMEI = strconv.FormatUint(unit, 10)
	if c.imei == "" {
		m.Login = true
	}
	c.imei = m.IMEI
}

func (c *codec) keepAlive(r *bufio.Reader) (*track.Message, error) {
	var b [12]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return nil, err
	}
	m := &track.Message{Kind: "keepalive", Reply: append([]byte(nil), b[:]...)}
	c.login(m, binary.BigEndian.Uint64(b[2:10]))
	return m, nil
}

func (c *codec) crcSkip() error {
	return &track.Skip{Warning: track.Warning{Code: "crcMismatch", Setting: "profile.checkCrc",
		Msg: "A packet whose CRC does not match was dropped. Set profile.checkCrc to false if the device computes it another way."}}
}

func (c *codec) binary(r *bufio.Reader) (*track.Message, error) {
	var h [6]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(h[4:6]))
	if n < 10 {
		return nil, fmt.Errorf("atrack: length %d is too short", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	if c.cfg.crc && track.CRC16IBM(append(append([]byte(nil), h[4:6]...), body...)) != binary.BigEndian.Uint16(h[2:4]) {
		return nil, c.crcSkip()
	}
	seq, unit := binary.BigEndian.Uint16(body[0:2]), binary.BigEndian.Uint64(body[2:10])
	m := &track.Message{Kind: "position", Reply: Ack(unit, seq)}
	c.login(m, unit)
	if string(h[:2]) == "@R" {
		return nil, &track.Skip{Reply: m.Reply, Warning: track.Warning{Code: "pictureNotRead", Detail: "@R",
			Msg: "A picture packet was acknowledged and passed over: pictures are not read."}}
	}
	rest := body[10:]
	for len(rest) >= minRecord(rest) {
		rec, more, err := c.binaryRecord(rest, &m.Warnings)
		if err != nil {
			m.Warnings = append(m.Warnings, track.Warning{Code: "shortRecord", Msg: "A record shorter than its fields was passed over: " + err.Error()})
			rest = nil
			break
		}
		m.Records = append(m.Records, rec)
		rest = more
	}
	if len(rest) > 0 && len(bytes.Trim(rest, "\x00")) > 0 {
		m.Warnings = append(m.Warnings, track.Warning{Code: "trailingBytes", Detail: fmt.Sprintf("%d bytes", len(rest)),
			Msg: "Bytes after the last record were passed over. Set profile.form to the device's AT$FORM custom fields if its records carry no %CI.", Setting: "profile.form"})
	}
	return m, nil
}

// readable reports whether a binary record's times are year..second
// (AT$FORM time format 1) rather than Unix seconds.
func readable(b []byte) bool {
	if len(b) < 2 {
		return false
	}
	y := binary.BigEndian.Uint16(b)
	return y >= 2000 && y < 2100
}

// minRecord is the size of a record without driver ID, text or custom
// fields.
func minRecord(b []byte) int {
	if readable(b) {
		return 3*7 + 29
	}
	return 3*4 + 29
}

type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil || len(r.b) < n {
		if r.err == nil {
			r.err = fmt.Errorf("needs %d more bytes, has %d", n, len(r.b))
		}
		return make([]byte, n)
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}
func (r *reader) u8() int     { return int(r.take(1)[0]) }
func (r *reader) u16() int    { return int(binary.BigEndian.Uint16(r.take(2))) }
func (r *reader) s16() int    { return int(int16(binary.BigEndian.Uint16(r.take(2)))) }
func (r *reader) u32() uint32 { return binary.BigEndian.Uint32(r.take(4)) }
func (r *reader) u64() uint64 { return binary.BigEndian.Uint64(r.take(8)) }
func (r *reader) str() string {
	if r.err != nil {
		return ""
	}
	i := bytes.IndexByte(r.b, 0)
	if i < 0 {
		r.err = errors.New("a string has no 0x00 end")
		return ""
	}
	s := string(r.b[:i])
	r.b = r.b[i+1:]
	return s
}

func (r *reader) time(long bool) time.Time {
	if long {
		b := r.take(7)
		y := int(binary.BigEndian.Uint16(b))
		if y == 0 {
			return time.Time{}
		}
		return time.Date(y, time.Month(b[2]), int(b[3]), int(b[4]), int(b[5]), int(b[6]), 0, time.UTC)
	}
	v := r.u32()
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(int64(v), 0).UTC()
}

// base is the standard part of a record, both forms.
type base struct {
	gps, rtc        time.Time
	lon, lat        float64
	heading, report int
	odometer        float64 // km
	hdop            float64
	inputs, outputs int
	speed           int
	adc             float64 // V
	driver          string
	temp1, temp2    int // 0.1 °C, 2000 none
	text            string
}

func (c *codec) record(b base) track.Record {
	rec := track.Record{Status: map[string]any{
		"event": b.report, "odometer": b.odometer, "inputs": b.inputs, "outputs": b.outputs, "adc1": b.adc,
	}}
	valid := !b.gps.IsZero() && (b.lat != 0 || b.lon != 0)
	t := b.gps
	if t.IsZero() {
		t = b.rtc
	}
	if t.IsZero() {
		t = time.Unix(0, 0).UTC()
	}
	rec.Time = t
	spd, hdg, hdop := float64(b.speed), float64(b.heading), b.hdop
	rec.Fix = &track.Fix{Time: t, Lat: b.lat, Lon: b.lon, Valid: valid, Speed: &spd, Heading: &hdg, HDOP: &hdop}
	if b.driver != "" {
		rec.Status["driverId"] = b.driver
	}
	if b.temp1 != 2000 {
		rec.Status["temp1"] = float64(b.temp1) / 10
	}
	if b.temp2 != 2000 {
		rec.Status["temp2"] = float64(b.temp2) / 10
	}
	if b.text != "" {
		rec.Status["text"] = b.text
	}
	if a, ok := c.cfg.alarms[b.report]; ok {
		rec.Alerts = append(rec.Alerts, a)
	}
	return rec
}

func (c *codec) binaryRecord(b []byte, warn *[]track.Warning) (track.Record, []byte, error) {
	r := &reader{b: b}
	long := readable(b)
	var x base
	x.gps = r.time(long)
	x.rtc = r.time(long)
	_ = r.time(long) // sending time
	x.lon = float64(int32(r.u32())) / 1e6
	x.lat = float64(int32(r.u32())) / 1e6
	x.heading = r.u16()
	x.report = r.u8()
	x.odometer = float64(r.u32()) / 10
	x.hdop = float64(r.u16()) / 10
	x.inputs = r.u8()
	x.speed = r.u16()
	x.outputs = r.u8()
	x.adc = float64(r.u16()) / 1000
	x.driver = r.str()
	x.temp1, x.temp2 = r.s16(), r.s16()
	x.text = r.str()
	if r.err != nil {
		return track.Record{}, nil, r.err
	}
	rec := c.record(x)
	form := c.cfg.form
	if bytes.HasPrefix(r.b, []byte("%CI")) {
		f, err := parseForm(r.str())
		if err != nil {
			*warn = append(*warn, track.Warning{Code: "badForm", Msg: "A record's custom-field layout could not be read: " + err.Error()})
			return rec, nil, nil
		}
		form = f[1:]
	}
	cus := customFields{rec: &rec}
	for _, k := range form {
		if !cus.binary(k, r) {
			*warn = append(*warn, track.Warning{Code: "unknownField", Detail: k, Setting: "profile.form",
				Msg: "A custom field of unknown size ended the record's reading; the rest of the packet was passed over."})
			return rec, nil, nil
		}
		if r.err != nil {
			return track.Record{}, nil, r.err
		}
	}
	cus.done()
	return rec, r.b, nil
}

// customFields collects AT$FORM fields into a record.
type customFields struct {
	rec            *track.Record
	mcc, mnc, lac  int
	cid            int64
	hasCN, hasCell bool
	gq             *int
}

// fixed sizes of binary custom fields; -1 is a 0x00-ended string.
var fieldSize = map[string]int{
	"SA": 1, "GQ": 1, "RL": 1, "GS": 1, "DT": 1, "EL": 1, "TR": 1, "FL": 1, "ML": 1, "PD": 1, "IA": 1, "MP": 1, "MT": 1,
	"IN0": 1, "IN1": 1, "IN2": 1, "IN3": 1, "HA": 1, "HB": 1, "HC": 1,
	"MV": 2, "BV": 2, "LC": 2, "RP": 2, "MF": 2, "ET": 2, "AV1": 2, "SM": 2,
	"CE": 4, "CN": 4, "PC": 4, "AT": 4, "FC": 4, "EO": 4, "EH": 4,
	"CM": 8, "ME": 8, "GV": 6, "GN": 60,
	"VN": -1, "CI": -1, "NC": -1, "GL": -1, "MA": -1, "CD": -1,
}

// sizeOf is a field's binary size; the J1939 and J1708 fields (Jxn, Zxn)
// have it in their second letter: O one byte, H two, L and N four, S a
// string.
func sizeOf(k string) (int, bool) {
	if n, ok := fieldSize[k]; ok {
		return n, true
	}
	if len(k) >= 3 && (k[0] == 'J' || k[0] == 'Z') {
		switch k[1] {
		case 'O':
			return 1, true
		case 'H':
			return 2, true
		case 'L', 'N':
			return 4, true
		case 'S':
			return -1, true
		}
	}
	return 0, false
}

func (f *customFields) binary(k string, r *reader) bool {
	n, ok := sizeOf(k)
	if !ok {
		return false
	}
	switch n {
	case -1:
		f.set(k, r.str())
	case 1:
		f.set(k, r.u8())
	case 2:
		if k == "ET" {
			f.set(k, r.s16())
		} else {
			f.set(k, r.u16())
		}
	case 4:
		f.set(k, int64(r.u32()))
	case 8:
		f.set(k, strconv.FormatUint(r.u64(), 10))
	default:
		f.set(k, fmt.Sprintf("%X", r.take(n)))
	}
	return true
}

func (f *customFields) text(k, v string) {
	v = strings.Trim(v, "\x1a \r\n")
	if n, err := strconv.ParseInt(v, 10, 64); err == nil && k != "VN" && k != "CD" && k != "CM" && k != "ME" && k != "CN" {
		if n >= math.MinInt32 && n <= math.MaxInt32 {
			f.set(k, int(n))
		} else {
			f.set(k, n)
		}
		return
	}
	f.set(k, v)
}

func toInt(v any) (int64, bool) {
	switch x := v.(type) {
	case int:
		return int64(x), true
	case int64:
		return x, true
	case string:
		n, err := strconv.ParseInt(x, 10, 64)
		return n, err == nil
	}
	return 0, false
}

// set keeps every field raw in Status["custom"] by its code and maps the
// documented ones to the record.
func (f *customFields) set(k string, v any) {
	rec := f.rec
	raw, _ := rec.Status["custom"].(map[string]any)
	if raw == nil {
		raw = map[string]any{}
		rec.Status["custom"] = raw
	}
	if k == "CI" {
		return
	}
	raw[k] = v
	n, isNum := toInt(v)
	switch k {
	case "SA":
		if isNum && rec.Fix != nil {
			rec.Fix.Sats = track.I(int(n))
		}
	case "MV":
		if isNum {
			rec.Status["externalVoltage"] = float64(n) / 10
		}
	case "BV":
		if isNum {
			rec.Status["batteryVoltage"] = float64(n) / 10
		}
	case "GQ":
		if isNum {
			g := int(n)
			f.gq = &g
			rec.Status["gsm"] = g
		}
	case "CE":
		f.cid, f.hasCell = n, isNum
	case "LC":
		f.lac = int(n)
	case "CN":
		s := fmt.Sprint(v)
		if len(s) > 3 {
			f.mcc, _ = strconv.Atoi(s[:3])
			f.mnc, _ = strconv.Atoi(s[3:])
			f.hasCN = f.mcc > 0
		}
	case "AT":
		if isNum && rec.Fix != nil {
			rec.Fix.Alt = track.F(float64(n))
		}
	case "RP":
		rec.Status["rpm"] = v
	case "DT":
		rec.History = isNum && n == 1
	case "VN", "ZS1", "JS1":
		if s, _ := v.(string); s != "" {
			rec.Status["vin"] = s
		}
	case "EL":
		rec.Status["engineLoad"] = v
	case "TR":
		rec.Status["throttle"] = v
	case "ET":
		rec.Status["coolantTemp"] = v
	case "FL":
		rec.Status["fuel"] = v
	case "FC":
		if isNum {
			rec.Status["fuelUsed"] = float64(n) / 10
		}
	case "CD":
		if s := fmt.Sprint(v); s != "" {
			rec.Status["iccid"] = s
		}
	case "CM":
		rec.Status["imsi"] = fmt.Sprint(v)
	case "IN0":
		rec.Status["ignition"] = isNum && n > 0
	case "IN1", "IN2", "IN3":
		rec.Status["din"+k[2:]] = isNum && n > 0
	case "MT":
		rec.Status["movement"] = isNum && n > 0
	case "HA", "HB", "HC":
		if isNum && n > 0 {
			t := map[string]string{"HA": "harsh-acceleration", "HB": "harsh-braking", "HC": "rash-turning"}[k]
			rec.Alerts = append(rec.Alerts, track.NewAlert(t, k))
		}
	}
}

func (f *customFields) done() {
	if f.hasCN && f.hasCell && f.cid != 0 {
		cell := track.Cell{MCC: f.mcc, MNC: f.mnc, LAC: f.lac, CID: f.cid}
		f.rec.Network = &track.Network{Cells: []track.Cell{cell}}
	}
}

func (c *codec) ascii(r *bufio.Reader) (*track.Message, error) {
	prefix := make([]byte, 3)
	if _, err := io.ReadFull(r, prefix); err != nil {
		return nil, err
	}
	crcField, err := field(r)
	if err != nil {
		return nil, err
	}
	lenField, err := field(r)
	if err != nil {
		return nil, err
	}
	n, err := strconv.Atoi(lenField)
	if err != nil || n < 1 || n > maxLen {
		return nil, fmt.Errorf("atrack: ASCII length %q", lenField)
	}
	rest := make([]byte, n-1)
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, err
	}
	tail := append([]byte(","+lenField+","), rest...)
	// A length that leaves the LF out: take it if it is already here (a
	// later one is skipped as a line end by Decode).
	if bytes.HasSuffix(rest, []byte("\r")) && r.Buffered() > 0 {
		if p, err := r.Peek(1); err == nil && p[0] == '\n' {
			_, _ = r.Discard(1)
			tail = append(tail, '\n')
		}
	}
	// ASCII CRCs of some firmware cannot be reproduced from the document's
	// rule; the comma-separated fields check themselves, so the packet is
	// kept with a warning.
	var crcWarn *track.Warning
	want, err := strconv.ParseUint(crcField, 16, 16)
	if c.cfg.crc && (err != nil || uint16(want) != track.CRC16IBM(tail)) && (err != nil || uint16(want) != track.CRC16IBM(bytes.TrimRight(tail, "\r\n"))) {
		crcWarn = &track.Warning{Code: "crcMismatch", Setting: "profile.checkCrc", Detail: crcField,
			Msg: "An ASCII packet whose CRC does not match was read anyway (its fields were well formed). Set profile.checkCrc to false to stop this warning."}
	}
	body := strings.TrimRight(string(rest), "\r\n")
	head := strings.SplitN(body, ",", 3)
	if len(head) < 3 {
		return nil, &track.Skip{Warning: track.Warning{Code: "shortPacket", Msg: "An ASCII packet without sequence and unit ID was passed over."}}
	}
	seq, err1 := strconv.ParseUint(head[0], 10, 32)
	unit, err2 := strconv.ParseUint(head[1], 10, 64)
	if err1 != nil || err2 != nil {
		return nil, &track.Skip{Warning: track.Warning{Code: "badHeader", Detail: head[0] + "," + head[1],
			Msg: "An ASCII packet whose sequence or unit ID is not a number was passed over."}}
	}
	m := &track.Message{Kind: "position", Reply: Ack(unit, uint16(seq))}
	c.login(m, unit)
	if crcWarn != nil {
		m.Warnings = append(m.Warnings, *crcWarn)
	}
	for _, line := range strings.Split(head[2], "\r\n") {
		line = strings.TrimLeft(line, "\n")
		if line == "" {
			continue
		}
		rec, ok := c.asciiRecord(line)
		if !ok {
			d := line
			if len(d) > 64 {
				d = d[:64]
			}
			m.Warnings = append(m.Warnings, track.Warning{Code: "badRecord", Detail: d, Msg: "An ASCII record that could not be read was passed over."})
			continue
		}
		m.Records = append(m.Records, rec)
	}
	return m, nil
}

// field reads up to the next comma (at most 16 bytes).
func field(r *bufio.Reader) (string, error) {
	var b []byte
	for len(b) <= 16 {
		x, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if x == ',' {
			return string(b), nil
		}
		b = append(b, x)
	}
	return "", errors.New("atrack: ASCII header field too long")
}

func asciiTime(s string) (time.Time, bool) {
	switch len(s) {
	case 14:
		t, err := time.Parse("20060102150405", s)
		return t, err == nil
	default:
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return time.Time{}, false
		}
		if n == 0 {
			return time.Time{}, true
		}
		return time.Unix(n, 0).UTC(), true
	}
}

func (c *codec) asciiRecord(line string) (track.Record, bool) {
	f := strings.SplitN(line, ",", 17)
	if len(f) < 16 {
		return track.Record{}, false
	}
	var x base
	var ok [6]bool
	x.gps, ok[0] = asciiTime(f[0])
	x.rtc, ok[1] = asciiTime(f[1])
	lon, e1 := strconv.Atoi(f[3])
	lat, e2 := strconv.Atoi(f[4])
	ok[2] = e1 == nil && e2 == nil
	x.lon, x.lat = float64(lon)/1e6, float64(lat)/1e6
	var e3, e4 error
	x.heading, e3 = strconv.Atoi(f[5])
	x.report, e4 = strconv.Atoi(f[6])
	ok[3] = e3 == nil && e4 == nil
	od, _ := strconv.ParseFloat(f[7], 64)
	x.odometer = math.Round(od*10) / 100
	hd, _ := strconv.ParseFloat(f[8], 64)
	x.hdop = hd / 10
	x.inputs, _ = strconv.Atoi(f[9])
	sp, e5 := strconv.ParseFloat(f[10], 64)
	x.speed, ok[4] = int(sp), e5 == nil
	x.outputs, _ = strconv.Atoi(f[11])
	adc, _ := strconv.Atoi(f[12])
	x.adc = float64(adc) / 1000
	x.driver = f[13]
	x.temp1, _ = strconv.Atoi(f[14])
	x.temp2, _ = strconv.Atoi(f[15])
	ok[5] = true
	for _, v := range ok {
		if !v {
			return track.Record{}, false
		}
	}
	var custom string
	if len(f) == 17 {
		rest := f[16]
		if i := strings.IndexByte(rest, 0x1A); i >= 0 {
			x.text, custom = rest[:i], strings.TrimPrefix(rest[i+1:], ",")
		} else if i := strings.IndexByte(rest, ','); i >= 0 {
			x.text, custom = rest[:i], rest[i+1:]
		} else {
			x.text = rest
		}
	}
	rec := c.record(x)
	form := c.cfg.form
	vals := splitValues(custom)
	if len(vals) > 0 && strings.HasPrefix(vals[0], "%CI") {
		if fm, err := parseForm(vals[0]); err == nil {
			form, vals = fm[1:], vals[1:]
		}
	}
	if len(form) > 0 && form[0] == "CI" && len(vals) > 0 {
		form, vals = form[1:], vals[1:]
	}
	cus := customFields{rec: &rec}
	for i, k := range form {
		if i >= len(vals) {
			break
		}
		cus.text(k, vals[i])
	}
	cus.done()
	return rec, true
}

// splitValues splits custom values at commas (values may end with 0x1A).
func splitValues(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

// errorReasons are our words for the AT command error codes.
var errorReasons = map[string]string{
	"101": "the device does not know this command",
	"102": "a command parameter is not valid",
	"103": "the command tag is not valid",
	"104": "the command password is wrong",
	"105": "the SIM PIN is wrong",
	"106": "no log data",
	"107": "no impact data",
	"108": "SMS is not supported",
}

func (c *codec) answer(r *bufio.Reader) (*track.Message, error) {
	line, err := r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return nil, errors.New("atrack: answer too long")
	}
	if err != nil && !(errors.Is(err, io.EOF) && len(line) > 0) {
		return nil, err
	}
	s := strings.TrimSpace(strings.TrimPrefix(string(line), "$"))
	m := &track.Message{IMEI: c.imei, Kind: "response"}
	name, val, hasVal := strings.Cut(s, "=")
	if i := strings.IndexByte(name, '+'); i >= 0 {
		name, m.Correlation = name[:i], name[i+1:]
	}
	resp := name
	if hasVal {
		resp = name + "=" + val
	}
	m.Response = &resp
	switch name {
	case "ERROR":
		m.Failed = true
		m.Details = map[string]any{"error": val}
		if why, ok := errorReasons[val]; ok {
			m.Details["reason"] = why
		}
	case "INFO":
		m.Details = info(val)
	}
	return m, nil
}

// info reads the AT$INFO answer: unit ID, model, firmware, IMEI, IMSI,
// ICCID, main and backup voltage (0.1 V), satellites, GSM status, signal,
// connection and antenna status.
func info(v string) map[string]any {
	f := strings.Split(v, ",")
	d := map[string]any{}
	keys := []string{"unitId", "model", "firmware", "imei", "imsi", "iccid"}
	for i, k := range keys {
		if i < len(f) && f[i] != "" {
			d[k] = f[i]
		}
	}
	num := func(i int) (int, bool) {
		if i >= len(f) {
			return 0, false
		}
		n, err := strconv.Atoi(f[i])
		return n, err == nil
	}
	if n, ok := num(6); ok {
		d["externalVoltage"] = float64(n) / 10
	}
	if n, ok := num(7); ok {
		d["batteryVoltage"] = float64(n) / 10
	}
	if n, ok := num(8); ok {
		d["sats"] = n
	}
	if n, ok := num(9); ok {
		d["gsmStatus"] = n
	}
	if n, ok := num(10); ok {
		d["gsm"] = n
	}
	return d
}
