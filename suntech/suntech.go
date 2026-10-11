// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package suntech is the Suntech tracker protocol of the ST300, ST340,
// ST4300, ST600 and SA200 families: frame reading, decoding into
// track.Message, and command framing with answer correlation.
//
// Suntech devices speak one of two text protocols, both with fields
// separated by ';' and each frame ending with a carriage return:
//
//   - the older one, whose header joins the model and the report type
//     ("ST300STT", "SA200ALT", "ST600EMG"), with a fixed field order per
//     model family;
//   - the Universal protocol of the newer firmware and the ST4300 family,
//     whose header is the report type alone ("STT", "ALT") followed by the
//     device ID and a hexadecimal field mask that says which fields follow.
//
// The device ID (the 6 to 10 digit serial number, not an IMEI) identifies
// the device on every frame; there is no separate login, so the codec
// marks the first identified frame as the login. The codec learns from the
// device's frames which protocol and model prefix it uses, and frames its
// commands the same way.
//
// Reports read: STT status, EMG emergency, EVT input event, ALT alert and
// UEX serial data (with the data's own length, so a carriage return inside
// the data does not end the frame), ALV keep-alive, and command answers
// (CMD;Res on the older protocol, RES on the Universal one). The Universal
// protocol's binary form (report types 0x81 and 0x82, the same mask-driven
// fields as binary values) is read too. Not read, passed over with a
// warning: the ST41x and ST9xx layouts (unknownModel), the compressed
// binary form starting 0x02 (zipFormat), BLE and BSA tag reports, the HTE
// travel report and the CRR crash dump (unknownMessage).
//
// Fields become: the fix (time, latitude, longitude, speed km/h, course,
// satellites, fix flag), the serving cell (Network, when the frame carries
// MCC, MNC and LAC; otherwise status cellId), the received signal level
// (status gsm, as the device reports it), odometer (km, from the device's
// metres), external and backup battery voltages, ignition, din1..din3,
// dout1..dout2, firmware, model, report mode and message number, the
// trailing hour meter (minutes), and the stored flag (Record.History).
// EMG and ALT codes become alerts where the code has an alert type of this
// module (emergency, main power, over-speed, geofences, low battery,
// vibration, impact, harsh acceleration and braking, jamming, door); every
// code is also in status (emergencyId, alertId, event).
//
// Commands are text ending with a carriage return. The raw form {"text":
// "ST300CMD;<id>;02;Enable1"} is sent as written. Named commands
// (track.Named):
//
//	                Universal              older protocol
//	engineStop      CMD;<id>;04;01         <model>CMD;<id>;02;Enable1    output 1 on (the immobiliser relay)
//	engineResume    CMD;<id>;04;02         <model>CMD;<id>;02;Disable1   output 1 off
//	locate          CMD;<id>;03;01         <model>CMD;<id>;02;StatusReq  report the position now
//	reboot          CMD;<id>;03;03         <model>CMD;<id>;02;Reboot     restart
//	interval        none by default: the reporting intervals are part of a
//	                parameter-setting command whose layout differs by model;
//	                set profile.namedCommands.interval
//
// The device answers a command with CMD;Res (older) or RES (Universal),
// which name the command: the codec is a track.Correlator. An answer that
// holds one of the failure words fails the command.
//
// The profile (NewCodec; Profile):
//
//	format: "auto"     # auto (learned from the device's frames), universal or legacy
//	model: ""          # the older protocol's model prefix for commands sent before the first report, such as ST300
//	namedCommands: {}  # action → full command text with {imei} (the device ID) and {seconds}; "" turns an action off
//	failureWords: []   # words that fail a command's answer (default error, fail, invalid)
package suntech

import (
	"bufio"
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

// Interval bounds a profile's interval template, in seconds.
var Interval = track.IntervalRange{Min: 1, Max: 86400}

// NamedActions are the named commands the codec frames by default.
var NamedActions = []string{track.ActionEngineStop, track.ActionEngineResume, track.ActionLocate, track.ActionReboot}

// Profile is the manufacturer-variation settings.
type Profile struct {
	// Format is the protocol commands are framed in before the device's
	// first frame says it: "auto" (the default), "universal" or "legacy".
	Format string `json:"format,omitempty"`
	// Model is the older protocol's header prefix (ST300, SA200, ST600),
	// used for commands until the device's frames name it.
	Model string `json:"model,omitempty"`
	// NamedCommands replaces the text of a named action: the whole
	// command without the final carriage return, with {imei} (the device
	// ID) and {seconds}; "" turns the action off.
	NamedCommands track.NamedTemplates `json:"namedCommands,omitempty"`
	// FailureWords are the words (any case) whose presence in an answer
	// fails its command.
	FailureWords []string `json:"failureWords,omitempty"`
}

var modelForm = regexp.MustCompile(`^S[A-Z][0-9]{3}$`)

type config struct {
	format  string
	model   string
	named   track.NamedTemplates
	failure []string
}

// NewCodec validates a profile (empty for the defaults) and returns a
// factory of codecs, one per connection. Each codec is a
// track.Correlator.
func NewCodec(raw json.RawMessage) (func() track.Codec, error) {
	var p Profile
	if err := track.StrictJSON(raw, &p); err != nil {
		return nil, err
	}
	switch p.Format {
	case "", "auto", "universal", "legacy":
	default:
		return nil, fmt.Errorf("format %q is not auto, universal or legacy", p.Format)
	}
	if p.Model != "" && !modelForm.MatchString(p.Model) {
		return nil, fmt.Errorf("model %q is not a Suntech header prefix such as ST300 or SA200", p.Model)
	}
	if p.Format == "legacy" && p.Model == "" {
		return nil, errors.New("format legacy needs model, the header prefix such as ST300")
	}
	if err := p.NamedCommands.Check(false); err != nil {
		return nil, err
	}
	for k, v := range p.NamedCommands {
		if strings.ContainsAny(v, "\r\n") {
			return nil, fmt.Errorf("namedCommands.%s: leave out the final carriage return; it is added", k)
		}
	}
	fw, err := track.FailureWords(p.FailureWords, "error", "fail", "invalid")
	if err != nil {
		return nil, err
	}
	cfg := &config{format: p.Format, model: p.Model, named: p.NamedCommands, failure: fw}
	return func() track.Codec { return &codec{cfg: cfg} }, nil
}

// codec is one connection's state: whether a frame identified the device
// yet, and the protocol and model prefix its frames use.
type codec struct {
	cfg       *config
	seen      bool
	universal bool
	prefix    string // the older protocol's model prefix, once seen
	known     bool   // the device's protocol is known from a frame
}

const maxFrame = 16 << 10

var errIncomplete = errors.New("suntech: frame incomplete")

// Decode reads the next frame.
func (c *codec) Decode(r *bufio.Reader) (*track.Message, error) {
	for {
		b, err := r.Peek(1)
		if err != nil {
			return nil, err
		}
		if b[0] != '\r' && b[0] != '\n' && b[0] != ' ' && b[0] != 0 {
			break
		}
		_, _ = r.ReadByte()
	}
	head, err := r.Peek(3)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	var m *track.Message
	switch {
	case head[0] == 0x02:
		return nil, skipZip(r, head)
	case head[1] == 0x00:
		m, err = c.binary(r, head)
	default:
		m, err = c.text(r)
	}
	if err == nil && m != nil && m.IMEI != "" && !c.seen {
		c.seen = true
		m.Login = true
	}
	return m, err
}

// text reads up to a carriage return that ends the frame: one inside a
// UEX report's serial data does not.
func (c *codec) text(r *bufio.Reader) (*track.Message, error) {
	var buf []byte
	for {
		part, err := r.ReadSlice('\r')
		buf = append(buf, part...)
		if errors.Is(err, bufio.ErrBufferFull) && len(buf) < maxFrame {
			continue
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			return nil, errors.New("suntech: a frame is longer than 16 KiB without its carriage return")
		}
		if err != nil {
			if errors.Is(err, io.EOF) && len(buf) > 0 {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
		s := strings.TrimSuffix(string(buf), "\r")
		m, perr := c.parse(s)
		if errors.Is(perr, errIncomplete) && len(buf) < maxFrame {
			continue // the carriage return belonged to serial data
		}
		return m, perr
	}
}

func skipMsg(code, detail, msg string) error {
	if len(detail) > 64 {
		detail = detail[:64]
	}
	return &track.Skip{Warning: track.Warning{Code: code, Detail: detail, Msg: msg}}
}

func unknown(s string) error {
	return skipMsg("unknownMessage", s, "A Suntech frame this codec does not read was passed over.")
}

// scanner walks a frame's ';'-separated fields, keeping byte offsets for
// serial data.
type scanner struct {
	s   string
	pos int
	end bool
}

func (sc *scanner) more() bool { return !sc.end }

// next is the next field ("" past the end).
func (sc *scanner) next() string {
	if sc.end {
		return ""
	}
	i := strings.IndexByte(sc.s[sc.pos:], ';')
	if i < 0 {
		v := sc.s[sc.pos:]
		sc.pos = len(sc.s)
		sc.end = true
		return v
	}
	v := sc.s[sc.pos : sc.pos+i]
	sc.pos += i + 1
	return v
}

// rest is everything after the current field.
func (sc *scanner) rest() string {
	if sc.end {
		return ""
	}
	return sc.s[sc.pos:]
}

// serial reads UEX serial data: its length field, then that many bytes
// and the checksum field. errIncomplete when the frame is shorter.
func (sc *scanner) serial(st map[string]any) error {
	n, err := strconv.Atoi(sc.next())
	if err != nil || n < 0 {
		return nil
	}
	if sc.end || sc.pos+n > len(sc.s) {
		return errIncomplete
	}
	data := sc.s[sc.pos : sc.pos+n]
	sc.pos += n
	switch {
	case sc.pos == len(sc.s):
		sc.end = true
	case sc.s[sc.pos] == ';':
		sc.pos++
		sc.next() // checksum
	default:
		// The length does not end at a separator: keep the frame and
		// read on from the next one.
		if i := strings.IndexByte(sc.s[sc.pos:], ';'); i >= 0 {
			sc.pos += i + 1
		} else {
			sc.end = true
		}
	}
	st["serialData"] = data
	if strings.HasPrefix(data, "GTSL|") {
		if p := strings.Split(data, "|"); len(p) > 4 && p[4] != "" {
			st["driverId"] = p[4]
		}
	}
	return nil
}

func digits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func validID(s string) bool { return digits(s) && len(s) >= 4 && len(s) <= 20 }

// parse reads a text frame without its carriage return.
func (c *codec) parse(s string) (*track.Message, error) {
	sc := &scanner{s: s}
	head := sc.next()
	switch {
	case len(head) == 3 && isUpper(head):
		return c.universalText(head, sc)
	case len(head) == 8 && head[0] == 'S' && isUpper(head[5:]):
		return c.legacy(head[:5], head[5:], sc)
	}
	return nil, unknown(s)
}

func isUpper(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return false
		}
	}
	return s != ""
}

func (c *codec) learn(universal bool, prefix string) {
	c.known, c.universal, c.prefix = true, universal, prefix
}

// response builds a command answer.
func (c *codec) response(id, text, corr string) *track.Message {
	return &track.Message{IMEI: id, Kind: "response", Response: &text, Correlation: corr,
		Failed: track.AnswerFailed(text, c.cfg.failure)}
}

// ---- the older protocol ------------------------------------------------------

func (c *codec) legacy(prefix, typ string, sc *scanner) (*track.Message, error) {
	switch {
	case strings.HasPrefix(prefix, "ST4"), strings.HasPrefix(prefix, "ST9"):
		return nil, skipMsg("unknownModel", prefix+typ,
			"A Suntech "+prefix+" frame was passed over: this codec does not read the ST41x and ST9xx layouts. Set the device to the Universal protocol if its firmware has it.")
	}
	switch typ {
	case "CMD":
		if sc.next() != "Res" {
			return nil, unknown(sc.s)
		}
		id := sc.next()
		if !validID(id) {
			return nil, unknown(sc.s)
		}
		c.learn(false, prefix)
		text := sc.rest()
		_ = sc.next() // firmware
		return c.response(id, text, sc.next()), nil
	case "ALV":
		id := sc.next()
		if !validID(id) {
			return nil, unknown(sc.s)
		}
		c.learn(false, prefix)
		return &track.Message{IMEI: id, Kind: "heartbeat"}, nil
	case "STT", "EMG", "EVT", "ALT", "UEX":
	default:
		return nil, unknown(sc.s)
	}
	id := sc.next()
	if !validID(id) {
		return nil, unknown(sc.s)
	}
	st := map[string]any{}
	if strings.HasPrefix(prefix, "ST3") || prefix == "ST500" || prefix == "ST600" {
		st["model"] = sc.next()
	}
	st["firmware"] = sc.next()
	at, ok := dateTime(sc.next(), sc.next())
	if !ok {
		return nil, skipMsg("badField", sc.s, "A Suntech report with an unreadable date or time was passed over.")
	}
	rec := track.Record{Time: at}
	if prefix != "ST500" {
		cell := sc.next()
		if prefix == "ST600" {
			rec.Network = network(cell, sc.next(), sc.next(), sc.next(), st)
			gsm(sc.next(), st)
		} else if cell != "" {
			st["cellId"] = cell
		}
	}
	fix := &track.Fix{Time: at}
	lat, e1 := strconv.ParseFloat(sc.next(), 64)
	lon, e2 := strconv.ParseFloat(sc.next(), 64)
	if e1 != nil || e2 != nil {
		return nil, skipMsg("badField", sc.s, "A Suntech report with unreadable coordinates was passed over.")
	}
	fix.Lat, fix.Lon = lat, lon
	speedCourse(fix, sc.next(), sc.next())
	if n, err := strconv.Atoi(sc.next()); err == nil {
		fix.Sats = track.I(n)
	}
	fix.Valid = sc.next() == "1"
	rec.Fix = fix
	if v, err := strconv.ParseFloat(sc.next(), 64); err == nil {
		st["odometer"] = v / 1000
	}
	if v, err := strconv.ParseFloat(sc.next(), 64); err == nil {
		st["externalVoltage"] = v
	}
	io := sc.next()
	ioOK := len(io) >= 6 && strings.Trim(io, "01") == ""
	if ioOK {
		st["ignition"] = io[0] == '1'
		for i := 1; i <= 3; i++ {
			st[fmt.Sprintf("din%d", i)] = io[i] == '1'
		}
		st["dout1"], st["dout2"] = io[4] == '1', io[5] == '1'
	}
	kind := "normal"
	switch typ {
	case "STT":
		setInt(st, "mode", sc.next())
		setInt(st, "msgNum", sc.next())
	case "EMG":
		code := sc.next()
		setInt(st, "emergencyId", code)
		if a, ok := emergencies[code]; ok {
			rec.Alerts = append(rec.Alerts, track.NewAlert(a, "EMG:"+code))
		}
		kind = "emergency"
	case "EVT":
		setInt(st, "event", sc.next())
	case "ALT":
		code := sc.next()
		setInt(st, "alertId", code)
		alertOf(&rec, code)
	case "UEX":
		if err := sc.serial(st); err != nil {
			return nil, err
		}
	}
	// Optional trailing fields of newer firmware: hour meter (minutes),
	// backup battery voltage, and the message type (1 live, 0 stored). Read
	// only after a well-formed I/O field: a model whose layout differs
	// (ST500) is not misread.
	if hm := sc.next(); ioOK && digits(hm) {
		n, _ := strconv.Atoi(hm)
		st["hourMeterMinutes"] = n
		if bv := sc.next(); strings.Contains(bv, ".") {
			if v, err := strconv.ParseFloat(bv, 64); err == nil && v < 100 {
				st["batteryVoltage"] = v
				if sc.next() == "0" {
					rec.History = true
				}
			}
		}
	}
	if rec.History {
		kind = "history"
	}
	rec.Status = st
	c.learn(false, prefix)
	return &track.Message{IMEI: id, Kind: kind, Records: []track.Record{rec}}, nil
}

// emergencies are EMG codes with an alert type.
var emergencies = map[string]string{
	"1": "emergency", "3": "main-power-removed", "5": "door-open", "6": "door-open", "8": "vibration",
}

// alerts are ALT codes with an alert type.
var alerts = map[string]string{
	"1": "over-speed", "5": "geofence-exit", "6": "geofence-enter", "14": "low-battery", "15": "vibration",
	"16": "impact", "40": "main-power-restored", "41": "main-power-removed", "42": "emergency",
	"46": "harsh-acceleration", "47": "harsh-braking", "50": "gsm-jamming", "132": "door-open",
}

func alertOf(rec *track.Record, code string) {
	if n, err := strconv.Atoi(code); err == nil {
		code = strconv.Itoa(n)
	}
	if a, ok := alerts[code]; ok {
		rec.Alerts = append(rec.Alerts, track.NewAlert(a, "ALT:"+code))
	}
}

func setInt(st map[string]any, key, v string) {
	if n, err := strconv.Atoi(v); err == nil {
		st[key] = n
	}
}

func gsm(v string, st map[string]any) { setInt(st, "gsm", v) }

// dateTime reads YYYYMMDD and HH:MM:SS (UTC).
func dateTime(d, t string) (time.Time, bool) {
	v, err := time.Parse("2006010215:04:05", d+t)
	return v, err == nil
}

func speedCourse(f *track.Fix, speed, course string) {
	if v, err := strconv.ParseFloat(speed, 64); err == nil {
		f.Speed = &v
	}
	if v, err := strconv.ParseFloat(course, 64); err == nil {
		f.Heading = &v
	}
}

// network is the serving cell: cell ID and LAC hexadecimal, MCC and MNC
// decimal. Without MCC it is nil and the cell ID goes into status.
func network(cell, mcc, mnc, lac string, st map[string]any) *track.Network {
	cid, e1 := strconv.ParseInt(cell, 16, 64)
	cc, e2 := strconv.Atoi(mcc)
	nc, e3 := strconv.Atoi(mnc)
	la, e4 := strconv.ParseInt(lac, 16, 32)
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || cid == 0 {
		if cell != "" {
			st["cellId"] = cell
		}
		return nil
	}
	return &track.Network{Cells: []track.Cell{{MCC: cc, MNC: nc, LAC: int(la), CID: cid}}}
}

// ---- the Universal protocol --------------------------------------------------

func (c *codec) universalText(typ string, sc *scanner) (*track.Message, error) {
	switch typ {
	case "RES":
		id := sc.next()
		if !validID(id) {
			return nil, unknown(sc.s)
		}
		c.learn(true, "")
		text := sc.rest()
		g := sc.next()
		a := sc.next()
		return c.response(id, text, g+";"+a), nil
	case "ALV":
		id := sc.next()
		if !validID(id) {
			return nil, unknown(sc.s)
		}
		c.learn(true, "")
		return &track.Message{IMEI: id, Kind: "heartbeat"}, nil
	case "STT", "ALT", "UEX":
	default:
		return nil, unknown(sc.s)
	}
	id := sc.next()
	if !validID(id) {
		return nil, unknown(sc.s)
	}
	mask, err := strconv.ParseUint(sc.next(), 16, 32)
	if err != nil {
		return nil, skipMsg("badField", sc.s, "A Suntech Universal report without a readable field mask was passed over.")
	}
	has := func(bit uint) bool { return mask>>bit&1 == 1 }
	st := map[string]any{}
	rec := track.Record{}
	if has(1) {
		st["model"] = sc.next()
	}
	if has(2) {
		st["firmware"] = sc.next()
	}
	if has(3) && sc.next() == "0" {
		rec.History = true
	}
	var d, t string
	if has(4) {
		d = sc.next()
	}
	if has(5) {
		t = sc.next()
	}
	at, timeOK := dateTime(d, t)
	var cell, mcc, mnc, lac string
	if has(6) {
		cell = sc.next()
	}
	if has(7) {
		mcc = sc.next()
	}
	if has(8) {
		mnc = sc.next()
	}
	if has(9) {
		lac = sc.next()
	}
	rec.Network = network(cell, mcc, mnc, lac, st)
	if has(10) {
		gsm(sc.next(), st)
	}
	var lat, lon string
	if has(11) {
		lat = sc.next()
	}
	if has(12) {
		lon = sc.next()
	}
	fix := &track.Fix{Time: at}
	var speed, course string
	if has(13) {
		speed = sc.next()
	}
	if has(14) {
		course = sc.next()
	}
	speedCourse(fix, speed, course)
	if has(15) {
		if n, err := strconv.Atoi(sc.next()); err == nil {
			fix.Sats = track.I(n)
		}
	}
	if has(16) {
		fix.Valid = sc.next() == "1"
	}
	if has(17) {
		bitsOf(sc.next(), "din", st, true)
	}
	if has(18) {
		bitsOf(sc.next(), "dout", st, false)
	}
	switch typ {
	case "ALT":
		if has(19) {
			code := sc.next()
			setInt(st, "alertId", code)
			alertOf(&rec, code)
		}
		if has(20) {
			st["alertModifier"] = sc.next()
		}
		if has(21) {
			if v := sc.next(); v != "" {
				st["alertData"] = v
			}
		}
	case "UEX":
		if err := sc.serial(st); err != nil {
			return nil, err
		}
	default:
		if has(19) {
			setInt(st, "mode", sc.next())
		}
		if has(20) {
			setInt(st, "reportType", sc.next())
		}
		if has(21) {
			setInt(st, "msgNum", sc.next())
		}
	}
	if has(22) {
		sc.next() // reserved
	}
	if has(23) && typ != "UEX" {
		assign, err := strconv.ParseUint(sc.next(), 16, 32)
		if err == nil {
			for i := uint(0); i < 32; i++ {
				if assign>>i&1 == 1 {
					st[fmt.Sprintf("assign%d", i+1)] = sc.next()
				}
			}
		}
	}
	for i := 1; sc.more(); i++ {
		if v := sc.next(); v != "" {
			st[fmt.Sprintf("extra%d", i)] = v
		}
	}
	if la, e1 := strconv.ParseFloat(lat, 64); e1 == nil && timeOK {
		if lo, e2 := strconv.ParseFloat(lon, 64); e2 == nil {
			fix.Lat, fix.Lon = la, lo
			rec.Fix = fix
		}
	}
	if timeOK {
		rec.Time = at
	}
	rec.Status = st
	c.learn(true, "")
	kind := "normal"
	if rec.History {
		kind = "history"
	}
	for _, a := range rec.Alerts {
		if a.Type == "emergency" && !rec.History {
			kind = "emergency"
		}
	}
	return &track.Message{IMEI: id, Kind: kind, Records: []track.Record{rec}}, nil
}

// bitsOf reads the Universal protocol's input or output state, a string
// of binary digits with bit 0 last: inputs bit 0 is the ignition, bit n
// input n; outputs bit n-1 is output n.
func bitsOf(s, prefix string, st map[string]any, inputs bool) {
	if s == "" || strings.Trim(s, "01") != "" {
		return
	}
	n := len(s)
	bit := func(i int) bool { return i < n && s[n-1-i] == '1' }
	if inputs {
		st["ignition"] = bit(0)
		for i := 1; i <= 3; i++ {
			st[fmt.Sprintf("%s%d", prefix, i)] = bit(i)
		}
		return
	}
	for i := 0; i < 2; i++ {
		st[fmt.Sprintf("%s%d", prefix, i+1)] = bit(i)
	}
}
