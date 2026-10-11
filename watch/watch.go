// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package watch is the text protocol of 3G / SeTracker-style children's
// watches and many low-cost trackers ("[SG*id*len*content]"): frame
// reading, decoding into track.Message, and command framing. Our own
// implementation from the watch "Communication Protocol" V1.7_C (3G
// Electronics, published on traccar.org); facts cross-checked against
// Traccar's decoder tests.
//
// A frame is "[" vendor (two characters: SG, 3G, CS, ZJ, …) "*" device ID
// "*" [index "*"] length (four hexadecimal digits) "*" content "]". Binary
// content (voice) escapes "}" "[" "]" "," "*" as 0x7D followed by 0x01 to
// 0x05; frames are found by matching brackets, so a WiFi name holding
// brackets stays inside its frame. Read:
//
//	LK[,steps,rolls,battery]   link keep-alive, answered LK (the first frame is the Login)
//	UD, UD2 (history), UD3, UD_LTE, UD_WCDMA, WT, WG, WAD   positions, not answered
//	AL, AL_LTE, ALCUSTOMER…    alarm positions, answered AL
//	INIT, TKQ, TKQ2            answered with themselves (INIT,1)
//	PULSE, heart, BLOOD, bphrt, TEMP, btemp2, oxygen   health readings
//	anything else              the device's answer to a command, named by its keyword
//
// A position is date (ddMMyy), time, A/V, latitude, N/S, longitude, E/W,
// speed, course, altitude, satellites, GSM signal (0-100), battery (%),
// steps, rolls, a hexadecimal status word (alarms in its high half: 16
// SOS, 17 low battery, 18 out of fence, 19 into fence, 20 watch taken
// off; low half: 0 low battery, 1 out of fence, 2 in fence), the cells
// (count, timing advance, MCC, MNC, then LAC, cell ID and signal each;
// decimal or hexadecimal) and the WiFi access points (count, then name,
// MAC and RSSI each). Voice, pictures and audio parts (TK, img, JXTK) are
// passed over with a warning (JXTK is acknowledged).
//
// Commands are frames with the device's vendor, ID and index form;
// devices that send "3G" are sent "SG", as Traccar does. Every command's
// answer repeats its keyword, so the codec is a strict track.Correlator.
// Forms: {"text": "CR"}, a named command, or {"sos": ["number", …]} (one
// to three SOS numbers, "SOS,a,b,c"). Useful texts: CR (locate now),
// UPLOAD,<seconds>, RESET, POWEROFF, SOS1,<number>, VERNO, TS.
//
// The profile (NewCodec; Profile):
//
//	speedUnit: kmh            # kmh (default, as devices send it), mph (as the document says), knots
//	commandVendor: ""         # vendor written on commands; default the device's (3G → SG)
//	namedCommands: {interval: "UPLOAD,{seconds}"}   # replaces a named command's text
//
// Named commands (track.Named): locate "CR", reboot "RESET", interval
// "UPLOAD,<seconds>" (10 to 86400 s). Watches have no engine relay.
package watch

import (
	"bufio"
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
	SpeedUnit     string               `json:"speedUnit,omitempty"`
	CommandVendor string               `json:"commandVendor,omitempty"`
	NamedCommands track.NamedTemplates `json:"namedCommands,omitempty"`
}

type config struct {
	speed  float64 // to km/h
	vendor string
	named  track.NamedTemplates
}

// NewCodec validates a profile (empty for the defaults) and returns a
// factory of codecs, one per connection.
func NewCodec(raw json.RawMessage) (func() track.Codec, error) {
	var p Profile
	if err := track.StrictJSON(raw, &p); err != nil {
		return nil, err
	}
	c := config{speed: 1, vendor: p.CommandVendor, named: p.NamedCommands}
	switch p.SpeedUnit {
	case "", "kmh":
	case "mph":
		c.speed = 1.609344
	case "knots":
		c.speed = 1.852
	default:
		return nil, fmt.Errorf("speedUnit %q is kmh, mph or knots", p.SpeedUnit)
	}
	if c.vendor != "" && (len(c.vendor) != 2 || strings.ContainsAny(c.vendor, "*[]}")) {
		return nil, errors.New("commandVendor is two characters, such as SG or 3G")
	}
	if err := p.NamedCommands.Check(false); err != nil {
		return nil, err
	}
	return func() track.Codec { return &codec{cfg: c} }, nil
}

type codec struct {
	cfg      config
	imei     string
	vendor   string
	hasIndex bool
}

// Frame is a decoded frame.
type Frame struct {
	Vendor, ID string
	// Index is the frame index of devices that send one ("" none).
	Index   string
	Length  int
	Content []byte
}

const maxFrame = 1 << 20

// Escape escapes binary content.
func Escape(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for _, x := range b {
		switch x {
		case '}':
			out = append(out, 0x7D, 0x01)
		case '[':
			out = append(out, 0x7D, 0x02)
		case ']':
			out = append(out, 0x7D, 0x03)
		case ',':
			out = append(out, 0x7D, 0x04)
		case '*':
			out = append(out, 0x7D, 0x05)
		default:
			out = append(out, x)
		}
	}
	return out
}

// Unescape reverses Escape.
func Unescape(b []byte) []byte {
	out := make([]byte, 0, len(b))
	for i := 0; i < len(b); i++ {
		if b[i] == 0x7D && i+1 < len(b) && b[i+1] >= 1 && b[i+1] <= 5 {
			out = append(out, "}[],*"[b[i+1]-1])
			i++
			continue
		}
		out = append(out, b[i])
	}
	return out
}

// ReadFrame reads one frame, skipping bytes until "[" and matching
// brackets to its end.
func ReadFrame(r *bufio.Reader) (*Frame, error) {
	for {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if b == '[' {
			break
		}
	}
	buf := []byte{}
	depth := 1
	for depth > 0 {
		b, err := r.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, io.ErrUnexpectedEOF
			}
			return nil, err
		}
		switch b {
		case '[':
			depth++
		case ']':
			depth--
		}
		if depth > 0 {
			buf = append(buf, b)
		}
		if len(buf) > maxFrame {
			return nil, errors.New("watch: frame too long")
		}
	}
	return parseFrame(buf)
}

func parseFrame(b []byte) (*Frame, error) {
	parts := strings.SplitN(string(b), "*", 5)
	if len(parts) < 4 {
		return nil, &track.Skip{Warning: track.Warning{Code: "badFrame", Detail: clip(string(b)),
			Msg: "A frame without vendor, ID, length and content was passed over."}}
	}
	f := &Frame{Vendor: parts[0], ID: parts[1]}
	rest := parts[2:]
	if len(parts) == 5 && isHex4(parts[2]) && isHex4(parts[3]) {
		f.Index, rest = parts[2], []string{parts[3], parts[4]}
	} else {
		rest = []string{parts[2], strings.Join(parts[3:], "*")}
	}
	n, err := strconv.ParseUint(rest[0], 16, 32)
	if err != nil {
		return nil, &track.Skip{Warning: track.Warning{Code: "badFrame", Detail: clip(string(b)),
			Msg: "A frame whose length is not hexadecimal was passed over."}}
	}
	f.Length = int(n)
	f.Content = Unescape([]byte(rest[1]))
	return f, nil
}

func isHex4(s string) bool {
	if len(s) != 4 {
		return false
	}
	_, err := strconv.ParseUint(s, 16, 16)
	return err == nil
}

func clip(s string) string {
	if len(s) > 64 {
		return s[:64]
	}
	return s
}

// Encode builds a frame: vendor, ID, index ("" none), length and content.
func Encode(vendor, id, index string, content []byte) []byte {
	h := "[" + vendor + "*" + id + "*"
	if index != "" {
		h += index + "*"
	}
	h += fmt.Sprintf("%04X*", len(content))
	return append(append([]byte(h), content...), ']')
}

func (c *codec) reply(f *Frame, content string) []byte {
	return Encode(f.Vendor, f.ID, f.Index, []byte(content))
}

func (c *codec) Decode(r *bufio.Reader) (*track.Message, error) {
	f, err := ReadFrame(r)
	if err != nil {
		return nil, err
	}
	m := &track.Message{IMEI: f.ID, Login: c.imei == ""}
	c.imei, c.vendor, c.hasIndex = f.ID, f.Vendor, f.Index != ""
	typ, data, _ := strings.Cut(string(f.Content), ",")
	up := strings.ToUpper(typ)
	switch {
	case up == "LK":
		m.Kind, m.Reply = "link", c.reply(f, "LK")
		st := map[string]any{}
		if v := strings.Split(data, ","); data != "" && len(v) >= 3 {
			st["steps"], st["rolls"], st["batteryLevel"] = atoi(v[0]), atoi(v[1]), atoi(v[2])
		}
		m.Records = []track.Record{{Status: st, Time: time.Now().UTC()}}
	case up == "INIT":
		m.Kind, m.Reply = "init", c.reply(f, "INIT,1")
	case up == "TKQ" || up == "TKQ2":
		m.Kind, m.Reply = "link", c.reply(f, typ)
	case strings.HasPrefix(up, "UD") || up == "WT" || up == "WG" || up == "WAD" || strings.HasPrefix(up, "AL"):
		if up == "WAD" {
			// Language first, then the position.
			_, data, _ = strings.Cut(data, ",")
		}
		rec, ok := c.position(data)
		if !ok {
			return nil, &track.Skip{Warning: track.Warning{Code: "badPosition", Detail: clip(string(f.Content)),
				Msg: "A position that could not be read was passed over."}}
		}
		rec.History = up == "UD2"
		m.Kind = "position"
		if strings.HasPrefix(up, "AL") {
			m.Kind, m.Reply = "alarm", c.reply(f, "AL")
			if len(rec.Alerts) == 0 {
				rec.Alerts = append(rec.Alerts, track.NewAlert("alarm", typ))
			}
		}
		m.Records = []track.Record{rec}
	case up == "TK" || up == "TK2" || up == "IMG" || up == "JXTK":
		sk := &track.Skip{Warning: track.Warning{Code: "mediaNotRead", Detail: typ,
			Msg: "A voice or picture frame was passed over: media is not read."}}
		if up == "JXTK" {
			sk.Reply = c.reply(f, "JXTKR,1")
		}
		return nil, sk
	default:
		resp := string(f.Content)
		m.Kind, m.Response, m.Correlation = "response", &resp, up
		if st := health(up, data); st != nil {
			m.Records = []track.Record{{Status: st, Time: time.Now().UTC()}}
		}
	}
	return m, nil
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

// health reads a health reading.
func health(typ, data string) map[string]any {
	v := strings.Split(data, ",")
	num := func(i int) (float64, bool) {
		if i >= len(v) {
			return 0, false
		}
		x, err := strconv.ParseFloat(strings.TrimSpace(v[i]), 64)
		return x, err == nil
	}
	st := map[string]any{}
	switch typ {
	case "PULSE", "HEART":
		if x, ok := num(0); ok {
			st["heartRate"] = int(x)
		}
	case "BLOOD", "BPHRT":
		if x, ok := num(0); ok {
			st["bloodPressureHigh"] = int(x)
		}
		if x, ok := num(1); ok {
			st["bloodPressureLow"] = int(x)
		}
		if x, ok := num(2); ok {
			st["heartRate"] = int(x)
		}
	case "TEMP":
		if x, ok := num(0); ok {
			st["bodyTemperature"] = x
		}
	case "BTEMP2":
		if x, ok := num(0); ok && x > 0 {
			if t, ok := num(1); ok {
				st["bodyTemperature"] = t
			}
		}
	case "OXYGEN":
		if x, ok := num(1); ok {
			st["bloodOxygen"] = int(x)
		}
	default:
		return nil
	}
	return st
}

// alarmBits are the alarm bits of the status word's high half.
var alarmBits = []struct {
	bit uint
	typ string
}{{16, "emergency"}, {17, "low-battery"}, {18, "geofence-exit"}, {19, "geofence-enter"}, {20, "tamper"}}

func coord(v, hemi string, neg string) (float64, bool) {
	x, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
	if err != nil {
		return 0, false
	}
	if x > 0 && strings.TrimSpace(hemi) == neg {
		x = -x
	}
	return x, true
}

func number(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, true
	}
	n, err := strconv.ParseInt(s, 16, 64)
	return n, err == nil
}

func (c *codec) position(data string) (track.Record, bool) {
	v := strings.Split(data, ",")
	if len(v) < 16 {
		return track.Record{}, false
	}
	t, err := time.Parse("020106150405", v[0]+v[1])
	if err != nil {
		return track.Record{}, false
	}
	lat, ok1 := coord(v[3], v[4], "S")
	lon, ok2 := coord(v[5], v[6], "W")
	if !ok1 || !ok2 {
		return track.Record{}, false
	}
	f := &track.Fix{Time: t, Lat: lat, Lon: lon, Valid: v[2] == "A"}
	if x, err := strconv.ParseFloat(v[7], 64); err == nil {
		x = math.Round(x*c.cfg.speed*1e6) / 1e6
		f.Speed = &x
	}
	if x, err := strconv.ParseFloat(v[8], 64); err == nil {
		f.Heading = &x
	}
	if x, err := strconv.ParseFloat(v[9], 64); err == nil {
		f.Alt = &x
	}
	f.Sats = track.I(atoi(v[10]))
	rec := track.Record{Fix: f, Time: t, Status: map[string]any{
		"gsm": atoi(v[11]), "batteryLevel": atoi(v[12]), "steps": atoi(v[13]), "rolls": atoi(v[14]),
	}}
	sw, err := strconv.ParseUint(strings.TrimSpace(v[15]), 16, 32)
	if err == nil {
		rec.Status["statusWord"] = fmt.Sprintf("%08X", sw)
		for _, a := range alarmBits {
			if sw&(1<<a.bit) != 0 {
				rec.Alerts = append(rec.Alerts, track.NewAlert(a.typ, fmt.Sprintf("bit%d", a.bit)))
			}
		}
		if sw>>16 == 0 && sw&0x7 != 0 {
			// Only the state half: low battery, out of or into a fence.
			rec.Status["lowBattery"] = sw&1 != 0
			switch {
			case sw&1 != 0:
				rec.Alerts = append(rec.Alerts, track.NewAlert("low-battery", "bit0"))
			case sw&2 != 0:
				rec.Alerts = append(rec.Alerts, track.NewAlert("geofence-exit", "bit1"))
			case sw&4 != 0:
				rec.Alerts = append(rec.Alerts, track.NewAlert("geofence-enter", "bit2"))
			}
		}
	}
	rec.Network = network(v[16:])
	return rec, true
}

// network reads the cells and WiFi access points after the status word.
func network(v []string) *track.Network {
	nw := &track.Network{}
	i := 0
	next := func() (string, bool) {
		if i >= len(v) {
			return "", false
		}
		i++
		return strings.TrimSpace(v[i-1]), true
	}
	if s, ok := next(); ok {
		n := atoi(s)
		if n > 0 {
			next() // timing advance
			mccS, _ := next()
			mncS, _ := next()
			mcc, mnc := atoi(mccS), atoi(mncS)
			for k := 0; k < n; k++ {
				lacS, ok1 := next()
				cidS, ok2 := next()
				rs, ok3 := next()
				if !ok1 || !ok2 || !ok3 {
					break
				}
				lac, _ := number(lacS)
				cid, _ := number(cidS)
				cell := track.Cell{MCC: mcc, MNC: mnc, LAC: int(lac), CID: cid}
				// Signal is 0-255 here, not dBm; kept only when negative (dBm).
				if r, err := strconv.Atoi(rs); err == nil && r < 0 {
					cell.RSSI = &r
				}
				nw.Cells = append(nw.Cells, cell)
			}
		}
	}
	if s, ok := next(); ok && s != "" {
		n := atoi(s)
		for k := 0; k < n; k++ {
			next() // name
			mac, ok1 := next()
			rs, ok2 := next()
			if !ok1 || !ok2 {
				break
			}
			if strings.Count(mac, ":") == 5 {
				ap := track.WiFiAP{MAC: strings.ToLower(mac)}
				if r, err := strconv.Atoi(rs); err == nil {
					ap.RSSI = &r
				}
				nw.WiFi = append(nw.WiFi, ap)
			}
		}
	}
	if len(nw.Cells) == 0 && len(nw.WiFi) == 0 {
		return nil
	}
	return nw
}
