// Package queclink is the Queclink @Track ASCII tracker protocol of the
// GV300, GV55, GV500 and GL300 families: frame reading, decoding into
// track.Message, report acknowledgements and command framing. Our own
// implementation from Queclink's published @Track Air Interface Protocol
// documents; the GV300N document, revision 3.01 (TRACGV300NAN001), is the
// reference for every field position below:
// https://controlsatperu.com/Manuales/GV300N/Document/GV300N%20@Track%20Air%20Interface%20Protocol%20V3.01.pdf
// (other family members: GV300 V2.40 at
// https://manualzz.com/doc/7953135/gv300-@track-air-interface-protocol-v2.40,
// GV350M V3.11 at https://www.traccar.org/protocol/5004-gl200/).
//
// Every frame is printable ASCII ending with '$', fields separated by ','.
// The fields after the message name are always the protocol version, the
// unique ID (the IMEI, which identifies the device on every frame; there is
// no separate login) and the device name; the last two are the send time
// and the count number.
//
//	+RESP:GTxxx,<version>,<imei>,<name>,…,<send time>,<count>$   report
//	+BUFF:GTxxx,…$                                               report stored while offline (history)
//	+ACK:GTHBD,<version>,<imei>,<name>,<send time>,<count>$      heartbeat, answered +SACK:GTHBD,<version>,<count>$
//	+ACK:GTxxx,<version>,<imei>,<name>,[<sub>,]<serial>,<send time>,<count>$   a command's acknowledgement
//
// Position blocks are <accuracy (HDOP, 0 no fix)>,<speed km/h>,<heading>,
// <altitude m>,<longitude>,<latitude>,<GPS UTC time YYYYMMDDHHMMSS>,<MCC>,
// <MNC>,<LAC hex>,<cell ID hex>,<reserved>, preceded by their number (a
// GTFRI may carry up to 15). Each block becomes a fix and its cell the
// record's track.Network; the mileage after the last block is the
// odometer (km). Handled reports: GTFRI/GTERI fixed reports (with hour
// meter, analogue inputs, backup battery percentage and the device status:
// motion state, ignition, digital inputs and outputs), GTRTL (the answer
// to locate), GTSOS emergency, GTSPD over-speed, GTHBM harsh braking /
// acceleration / turning, GTIGN/GTIGF/GTIGL ignition, GTTOW towing,
// GTMPN/GTMPF main power, GTBPL low backup battery, GTGEO/GTGIN/GTGOT
// geofences, GTCRA crash, GTJDR/GTJDS jamming, GTDIS digital inputs, GTEPS
// external voltage, GTSTT motion state, GTBTC/GTSTC charging, GTINF device
// information, GTBAT, GTCSQ, GTCID and GTVER query answers, GTPNA/GTPFA
// power on and off, and the other position reports of the document (GTDOG,
// GTIOB, GTANT, GTIDN/GTIDF, GTSTR/GTSTP/GTLSP, GTGSS, GTFLA, GTDOS, GTAIS,
// GTIDA). Other configuration and data reports are accepted without
// values; a report this package does not know is passed over with the
// warning queclink.unknownMessage.
//
// The HEX (binary) format (AT+GTSRI or AT+GTQSS <Protocol Format> 1) is
// read on the same connection, told apart by its header: +RSP/+BSP
// location reports, +EVT/+BVT event reports (B: from the buffer, history),
// +INF/+BNF information reports, +HBD heartbeats (answered with the ASCII
// +SACK:GTHBD) and +ACK command acknowledgements (correlated like the
// ASCII ones), with the items AT+GTHRM's masks select; see hex.go. A HEX
// frame that names the device by its device name is read when an earlier
// frame on the connection gave the IMEI. The GV300N's factory masks name
// the device by its device name; clear those bits so that every frame
// carries the IMEI, for example
// AT+GTHRM=<password>,,,6F,3FEFFBF,3FEFFBF,FF7D,EF,,,,,,0001$. Crash data (+CRD), +DAT and +CAN
// frames are passed over with queclink.unknownMessage, a HEX frame that
// does not decode with queclink.messageUnreadable.
//
// Commands are AT+GTxxx=<password>,…,<serial>$. The raw form
// {"text": "AT+GTRTO=gv300,1,,,,,,0001$"} is sent as written (a missing
// final '$' is added). Named commands (track.Named):
//
//	engineStop    AT+GTOUT=<password>,1,,,0,0,0,0,0,0,0,,,,,,,<serial>$   digital output 1 on (the relay; outputs 2 and 3 off)
//	engineResume  AT+GTOUT=<password>,0,,,0,0,0,0,0,0,0,,,,,,,<serial>$   digital output 1 off
//	locate        AT+GTRTO=<password>,1,,,,,,<serial>$                    real-time operation RTL: report the position now (+RESP:GTRTL)
//	reboot        AT+GTRTO=<password>,3,,,,,,<serial>$                    real-time operation REBOOT
//	interval      AT+GTFRI=<password>,1,,,,,,,<seconds>,,,,,,,,,,<serial>$  fixed timing report every 5 to 86400 s
//
// The codec is a track.PasswordCommander: the password is the one passed
// to CommandWithPassword (the device's own), else profile.password (a
// Queclink device's factory password is its model name, such as gv300);
// Command uses profile.password. A profile's namedCommands text is the
// command without its serial and the final '$', which the codec appends.
// The device acknowledges a command it accepts with +ACK:GTxxx carrying
// the command's serial number; the codec is a track.Correlator, so that
// acknowledgement completes the command, and one with another serial (a
// late answer to an earlier command) does not. A command with a wrong
// password or wrong fields gets no acknowledgement at all, so it ends
// with a timeout.
//
// The profile (NewCodec; Profile):
//
//	password: ""          # command password of devices without their own (default none)
//	sack: false           # answer every report with +SACK:<count>$ (default false; turn on when the device's SACK Enable is 1 or 2)
//	namedCommands: {}     # action → command text without ",<serial>$", with {password} and {seconds} (default the table above)
//	alerts: {}            # extra report names → alert type, such as {"GTPFA": "tamper"} (default none)
package queclink

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cB-Sigma/trackers/track"
)

// Interval bounds the fixed timing report (AT+GTFRI <Send Interval>).
var Interval = track.IntervalRange{Min: 5, Max: 86400}

// NamedActions are the named commands the protocol has: all of them.
var NamedActions = track.Actions

// Profile is the manufacturer-variation settings.
type Profile struct {
	// Password is the command password of devices that have no password
	// of their own (CommandWithPassword with ""). A Queclink device's factory password
	// is its model name in lower case (gv300, gl300); AT+GTCFG changes it.
	Password string `json:"password,omitempty"`
	// Sack answers every report and acknowledgement with +SACK:<count>$.
	// Turn it on when the devices' SACK Enable (AT+GTSRI or AT+GTQSS) is 1
	// or 2; heartbeats are always answered.
	Sack bool `json:"sack,omitempty"`
	// NamedCommands replaces the command text of a named action for
	// firmware that differs: the text up to and without ",<serial>$", with
	// {password} and, for interval, {seconds}; "" turns the action off.
	NamedCommands track.NamedTemplates `json:"namedCommands,omitempty"`
	// Alerts maps further report names (GTxxx) to alert types, added to
	// or replacing the built-in ones.
	Alerts map[string]string `json:"alerts,omitempty"`
}

// defaultNamed are the named commands without ",<serial>$".
var defaultNamed = map[string]string{
	track.ActionEngineStop:   "AT+GTOUT={password},1,,,0,0,0,0,0,0,0,,,,,,",
	track.ActionEngineResume: "AT+GTOUT={password},0,,,0,0,0,0,0,0,0,,,,,,",
	track.ActionLocate:       "AT+GTRTO={password},1,,,,,",
	track.ActionReboot:       "AT+GTRTO={password},3,,,,,",
	track.ActionInterval:     "AT+GTFRI={password},1,,,,,,,{seconds},,,,,,,,,",
}

var reportName = regexp.MustCompile(`^GT[A-Z0-9]{3}$`)

type config struct {
	password string
	sack     bool
	named    track.NamedTemplates
	alerts   map[string]string
}

// NewCodec validates a profile (empty for the defaults) and returns a
// factory of codecs, one per connection. Each codec is a
// track.PasswordCommander and a track.Correlator.
func NewCodec(raw json.RawMessage) (func() track.Codec, error) {
	var p Profile
	if err := track.StrictJSON(raw, &p); err != nil {
		return nil, err
	}
	if err := p.NamedCommands.Check(true); err != nil {
		return nil, err
	}
	for k, v := range p.NamedCommands {
		if v != "" && !strings.HasPrefix(v, "AT+GT") {
			return nil, fmt.Errorf("namedCommands.%s: a Queclink command starts with AT+GT", k)
		}
		if strings.Contains(v, "$") {
			return nil, fmt.Errorf("namedCommands.%s: leave out the serial number and the final '$'; they are added to each command", k)
		}
	}
	if strings.ContainsAny(p.Password, ",$") {
		return nil, errors.New("password must not contain ',' or '$'")
	}
	cfg := config{password: p.Password, sack: p.Sack, named: p.NamedCommands, alerts: map[string]string{}}
	for k, v := range p.Alerts {
		if !reportName.MatchString(k) {
			return nil, fmt.Errorf("alerts: %q is not a report name such as GTPFA", k)
		}
		if strings.TrimSpace(v) == "" {
			return nil, fmt.Errorf("alerts.%s: name the alert type", k)
		}
		cfg.alerts[k] = v
	}
	return func() track.Codec {
		var b [2]byte
		_, _ = rand.Read(b[:])
		return &codec{cfg: &cfg, base: uint32(binary.BigEndian.Uint16(b[:]))}
	}, nil
}

// codec is one connection's state. base offsets the serial numbers of the
// connection's commands, so that the serials of a new connection do not
// repeat those of the last one (whose late acknowledgements may still
// come).
type codec struct {
	cfg  *config
	base uint32
	seen bool
	imei string // the connection's device, for HEX frames that carry its name
}

const maxFrame = 16 << 10

// Decode reads the next frame.
func (c *codec) Decode(r *bufio.Reader) (*track.Message, error) {
	// Resynchronise on '+': line ends and noise between frames are passed over.
	for {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if b == '+' {
			break
		}
	}
	head, _ := r.Peek(5)
	h := string(head)
	switch {
	case strings.HasPrefix(h, "RESP:"), strings.HasPrefix(h, "BUFF:"), strings.HasPrefix(h, "ACK:"):
	case len(h) >= 1 && h[0] == 0, len(h) >= 4 && hexHeaders[h[:3]] && h[3] != ':':
		frame, err := readHex(r)
		if err != nil {
			return nil, err
		}
		m, err := c.parseHex(frame)
		return c.identified(m, err)
	case len(h) >= 4 && isUpper(h[:3]) && h[3] != ':':
		return nil, c.skipBinary(r, h[:3])
	default:
		return nil, track.ErrSkip
	}
	var buf []byte
	for {
		part, err := r.ReadSlice('$')
		buf = append(buf, part...)
		if err == nil {
			break
		}
		if errors.Is(err, bufio.ErrBufferFull) && len(buf) < maxFrame {
			continue
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			return nil, errors.New("queclink: a frame is longer than 16 KiB without its final '$'")
		}
		if errors.Is(err, io.EOF) && len(buf) > 0 {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return c.identified(c.parse(strings.TrimSuffix(string(buf), "$")))
}

// identified marks the connection's first frame with an IMEI as its login
// and keeps the IMEI for HEX frames that carry the device name.
func (c *codec) identified(m *track.Message, err error) (*track.Message, error) {
	if err == nil && m != nil && m.IMEI != "" {
		if !c.seen {
			c.seen = true
			m.Login = true
		}
		c.imei = m.IMEI
	}
	return m, err
}

func isUpper(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 'A' || s[i] > 'Z' {
			return false
		}
	}
	return s != ""
}

// skipBinary passes over a binary frame of a header this codec does not
// know: it ends with 0x0D 0x0A.
func (c *codec) skipBinary(r *bufio.Reader, header string) error {
	n := 0
	prev := byte(0)
	for n < 4096 {
		b, err := r.ReadByte()
		if err != nil {
			break
		}
		n++
		if prev == 0x0D && b == 0x0A {
			break
		}
		prev = b
	}
	return &track.Skip{Warning: track.Warning{Code: "unknownCodec", Detail: "+" + header,
		Msg: "A Queclink binary frame with a header this codec does not know was passed over."}}
}

func unknown(text string) error {
	if len(text) > 64 {
		text = text[:64]
	}
	return &track.Skip{Warning: track.Warning{Code: "unknownMessage", Detail: text,
		Msg: "A message this codec does not read was passed over."}}
}

// parse reads one frame without its '$': "RESP:GTFRI,…".
func (c *codec) parse(s string) (*track.Message, error) {
	kind, rest, ok := strings.Cut(s, ":")
	if !ok {
		return nil, unknown(s)
	}
	f := strings.Split(rest, ",")
	for i := range f {
		f[i] = strings.TrimSpace(f[i])
	}
	if len(f) < 4 || !reportName.MatchString(f[0]) {
		return nil, unknown(s)
	}
	name := f[0]
	m := &track.Message{IMEI: imeiOf(f), Kind: "normal"}
	if m.IMEI == "" {
		return nil, unknown(s)
	}
	count := f[len(f)-1]
	sent := ts(f[len(f)-2])
	if kind == "ACK" {
		if name == "GTHBD" {
			m.Kind = "heartbeat"
			m.Reply = []byte("+SACK:GTHBD," + f[1] + "," + count + "$")
			m.Records = []track.Record{{Time: sent, Status: map[string]any{"protocolVersion": f[1]}}}
			return m, nil
		}
		if len(f) < 7 {
			return nil, unknown(s)
		}
		serial := strings.ToUpper(f[len(f)-3])
		text := "+" + s + "$"
		m.Kind = "response"
		m.Response = &text
		m.Correlation = name + "/" + serial
		m.Details = map[string]any{"ack": name, "serial": serial}
		if len(f) >= 8 && f[4] != "" {
			m.Details["subCommand"] = f[4]
		}
		c.sack(m, count)
		return m, nil
	}
	if kind != "RESP" && kind != "BUFF" {
		return nil, unknown(s)
	}
	history := kind == "BUFF"
	if history {
		m.Kind = "history"
	}
	recs, known := c.report(name, f, sent)
	if !known {
		return nil, unknown(s)
	}
	for i := range recs {
		recs[i].History = history
		if recs[i].Time.IsZero() {
			recs[i].Time = sent
		}
		for _, a := range recs[i].Alerts {
			if a.Type == "emergency" && !history {
				m.Kind = "emergency"
			}
		}
	}
	m.Records = recs
	c.sack(m, count)
	return m, nil
}

func (c *codec) sack(m *track.Message, count string) {
	if c.cfg.sack {
		m.Reply = []byte("+SACK:" + count + "$")
	}
}

// imeiOf is the unique ID: the third field, or (some data reports put
// other fields first) the first field of 15 digits.
func imeiOf(f []string) string {
	if digits(f[2]) && len(f[2]) >= 8 {
		return f[2]
	}
	for i := 1; i < min(len(f), 8); i++ {
		if len(f[i]) == 15 && digits(f[i]) {
			return f[i]
		}
	}
	return ""
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

// ts reads YYYYMMDDHHMMSS (UTC); zero when absent or malformed.
func ts(s string) time.Time {
	if len(s) != 14 || !digits(s) {
		return time.Time{}
	}
	t, err := time.Parse("20060102150405", s)
	if err != nil {
		return time.Time{}
	}
	return t
}

// Report names whose fields hold position blocks.
var positional = map[string]bool{}

// Report names accepted without values (configuration read-backs, data
// transfers, queries this package does not decode).
var silent = map[string]bool{}

func init() {
	for _, n := range strings.Fields(`GTFRI GTERI GTTOW GTDIS GTIOB GTSPD GTSOS GTRTL GTDOG GTIGL GTHBM GTGEO GTGIN GTGOT GTEPS
		GTAIS GTMPN GTMPF GTBTC GTSTC GTBPL GTSTT GTANT GTIGN GTIGF GTIDN GTIDF GTSTR GTSTP GTLSP GTGSS GTJDR GTJDS GTCRA
		GTFLA GTDOS GTIDA GTGES GTLBC GTTMP GTRMD GTPHL GTPNL`) {
		positional[n] = true
	}
	for _, n := range strings.Fields(`GTPDP GTGPS GTIOS GTTMZ GTAIF GTALL GTALM GTALS GTALC GTGSM GTGSV GTUVN GTCVN GTDAT
		GTDTT GTUDT GTCRD GTACC GTCAN GTPHD`) {
		silent[n] = true
	}
}

// block is one position block's first field index.
const blockLen = 12

// findBlock is the index of the first position block: an HDOP of 0 to 50,
// numbers or empty fields for speed, heading, altitude, longitude and
// latitude, and a 14-digit GPS time.
func findBlock(f []string, from int) int {
	for i := from; i+6 < len(f)-2; i++ {
		if !digits(f[i]) {
			continue
		}
		if a, _ := strconv.Atoi(f[i]); a > 50 {
			continue
		}
		ok := len(f[i+6]) == 14 && digits(f[i+6])
		for j := i + 1; ok && j <= i+5; j++ {
			if f[j] != "" {
				if _, err := strconv.ParseFloat(f[j], 64); err != nil {
					ok = false
				}
			}
		}
		if ok {
			return i
		}
	}
	return -1
}

// position reads the block at i: its fix (nil without coordinates) and
// cell.
func position(f []string, i int) (*track.Fix, *track.Network) {
	acc, _ := strconv.Atoi(f[i])
	var x *track.Fix
	lon, e1 := strconv.ParseFloat(f[i+4], 64)
	lat, e2 := strconv.ParseFloat(f[i+5], 64)
	if e1 == nil && e2 == nil && math.Abs(lat) <= 90 && math.Abs(lon) <= 180 {
		x = &track.Fix{Time: ts(f[i+6]), Lat: lat, Lon: lon, Valid: acc > 0 && (lat != 0 || lon != 0)}
		if acc > 0 {
			x.HDOP = track.F(float64(acc))
		}
		if v, err := strconv.ParseFloat(f[i+1], 64); err == nil {
			x.Speed = &v
		}
		if v, err := strconv.ParseFloat(f[i+2], 64); err == nil {
			x.Heading = &v
		}
		if v, err := strconv.ParseFloat(f[i+3], 64); err == nil {
			x.Alt = &v
		}
	}
	var n *track.Network
	if i+10 < len(f) {
		mcc, e1 := strconv.Atoi(f[i+7])
		mnc, e2 := strconv.Atoi(f[i+8])
		lac, e3 := strconv.ParseInt(f[i+9], 16, 32)
		cid, e4 := strconv.ParseInt(f[i+10], 16, 64)
		if e1 == nil && e2 == nil && e3 == nil && e4 == nil && (lac != 0 || cid != 0) {
			n = &track.Network{Cells: []track.Cell{{MCC: mcc, MNC: mnc, LAC: int(lac), CID: cid}}}
		}
	}
	return x, n
}

// typeNibble is the report type (the low hex digit of Report ID/Type).
func typeNibble(s string) int {
	if len(s) != 2 {
		return -1
	}
	v, err := strconv.ParseUint(s[1:], 16, 8)
	if err != nil {
		return -1
	}
	return int(v)
}

// idNibble is the report ID (the high hex digit).
func idNibble(s string) int {
	if len(s) != 2 {
		return -1
	}
	v, err := strconv.ParseUint(s[:1], 16, 8)
	if err != nil {
		return -1
	}
	return int(v)
}

// report decodes a +RESP/+BUFF report's records; known is false for a
// report name this package does not read.
func (c *codec) report(name string, f []string, sent time.Time) ([]track.Record, bool) {
	st := map[string]any{}
	var alerts []track.Alert
	alert := func(typ string) { alerts = append(alerts, track.NewAlert(typ, name)) }
	var recs []track.Record
	if positional[name] {
		i := findBlock(f, 4)
		end := 4
		if i >= 0 {
			// The reports with a report ID/type put it and the number of
			// positions before the first block.
			n, rt := 1, ""
			if i-2 >= 4 && len(f[i-2]) == 2 {
				rt = f[i-2]
				if v, err := strconv.Atoi(f[i-1]); err == nil && v > 1 && v <= 15 {
					n = v
				}
			}
			for k := 0; k < n && i+k*blockLen+6 < len(f)-2; k++ {
				j := i + k*blockLen
				if len(f[j+6]) != 14 && k > 0 {
					break
				}
				x, net := position(f, j)
				recs = append(recs, track.Record{Fix: x, Network: net})
				end = j + blockLen
			}
			c.typed(name, rt, f, i, st, alert)
		} else {
			c.typed(name, "", f, -1, st, alert)
		}
		tail := []string{}
		if end < len(f)-2 && i >= 0 {
			tail = f[end : len(f)-2]
		}
		c.tail(name, f, tail, st)
	} else {
		switch name {
		case "GTINF":
			info(f, st)
		case "GTBAT":
			// power present, external VCC mV, reserved, backup battery V, charging, LED
			if len(f) >= 10 {
				power(f[4], f[5], f[7], f[8], st)
			}
		case "GTCSQ":
			if v, err := strconv.Atoi(f[4]); err == nil && v != 99 {
				st["gsm"] = v
			}
		case "GTCID":
			st["iccid"] = f[4]
		case "GTVER":
			if len(f) >= 7 {
				st["deviceType"], st["firmware"], st["hardware"] = f[4], f[5], f[6]
			}
		case "GTPNA":
			st["devicePower"] = true
		case "GTPFA":
			st["devicePower"] = false
		default:
			if !silent[name] {
				if _, extra := c.cfg.alerts[name]; !extra {
					return nil, false
				}
			}
		}
	}
	if t, ok := c.cfg.alerts[name]; ok {
		alerts = []track.Alert{track.NewAlert(t, name)}
	}
	if len(recs) == 0 {
		recs = []track.Record{{}}
	}
	last := &recs[len(recs)-1]
	if len(st) > 0 {
		last.Status = st
	}
	last.Alerts = alerts
	if last.Time.IsZero() && last.Fix != nil && !last.Fix.Time.IsZero() {
		last.Time = last.Fix.Time
	}
	if len(st) == 0 && len(alerts) == 0 && last.Fix == nil && last.Network == nil && len(recs) == 1 {
		return nil, true // nothing to record; the frame still identifies the device
	}
	return recs, true
}

// typed reads what a report's name and report ID/type mean.
func (c *codec) typed(name, rt string, f []string, block int, st map[string]any, alert func(string)) {
	typ, id := typeNibble(rt), idNibble(rt)
	// The field before the position block in the reports that put a
	// value there (GTEPS voltage, GTBPL battery, GTSTT state, GTIGN/IGF
	// duration).
	pre := ""
	if block >= 5 {
		pre = f[4]
	}
	switch name {
	case "GTSOS":
		alert("emergency")
	case "GTSPD":
		if typ == 0 {
			alert("over-speed")
		}
	case "GTHBM":
		switch typ {
		case 0:
			alert("harsh-braking")
		case 1:
			alert("harsh-acceleration")
		case 2:
			alert("rash-turning")
		case 3:
			alert("harsh-braking")
			alert("rash-turning")
		case 4:
			alert("harsh-acceleration")
			alert("rash-turning")
		}
	case "GTIGN":
		st["ignition"] = true
		alert("ignition-on")
	case "GTIGF":
		st["ignition"] = false
		alert("ignition-off")
	case "GTIGL":
		switch typ {
		case 0:
			st["ignition"] = true
			alert("ignition-on")
		case 1:
			st["ignition"] = false
			alert("ignition-off")
		}
	case "GTTOW":
		alert("towing")
	case "GTMPF":
		st["mainPower"] = false
		alert("main-power-removed")
	case "GTMPN":
		st["mainPower"] = true
		alert("main-power-restored")
	case "GTBPL":
		if v, err := strconv.ParseFloat(pre, 64); err == nil {
			st["batteryVoltage"] = v
		}
		alert("low-battery")
	case "GTGEO":
		switch typ {
		case 0:
			alert("geofence-exit")
		case 1:
			alert("geofence-enter")
		}
		if id >= 0 {
			st["geofence"] = id
		}
	case "GTGIN":
		alert("geofence-enter")
	case "GTGOT":
		alert("geofence-exit")
	case "GTCRA":
		alert("impact")
	case "GTJDR", "GTJDS":
		// The GV300 family's jamming detection watches the mobile network.
		alert("gsm-jamming")
	case "GTDIS":
		if id >= 1 && typ >= 0 {
			st[fmt.Sprintf("din%d", id)] = typ == 1
		}
	case "GTEPS":
		if v, err := strconv.Atoi(pre); err == nil {
			st["externalVoltage"] = float64(v) / 1000
		}
	case "GTSTT":
		motion(pre, st)
	case "GTBTC":
		st["charging"] = true
	case "GTSTC":
		st["charging"] = false
	case "GTIDN":
		st["idling"] = true
	case "GTIDF":
		st["idling"] = false
	case "GTFRI", "GTERI":
		// GV300N and later: the external power voltage (mV) before the
		// report ID, when AT+GTEPS asks for it.
		if len(f) > 5 && len(f[5]) == 2 {
			if v, err := strconv.Atoi(f[4]); err == nil {
				st["externalVoltage"] = float64(v) / 1000
			}
		}
	}
}

var hourMeter = regexp.MustCompile(`^\d{1,5}:\d{2}:\d{2}$`)

// tail reads the fields after the last position block: the mileage, and in
// fixed reports the hour meter, analogue inputs, backup battery percentage
// and device status.
func (c *codec) tail(name string, f, tail []string, st map[string]any) {
	if len(tail) == 0 {
		return
	}
	k := 0
	if hourMeter.MatchString(tail[0]) { // GTIGN/GTIGF: hour meter, then mileage
		st["hourMeter"] = tail[0]
		k = 1
	}
	if k < len(tail) && strings.Contains(tail[k], ".") {
		if v, err := strconv.ParseFloat(tail[k], 64); err == nil {
			st["odometer"] = v
		}
		k++
	}
	if name != "GTFRI" && name != "GTERI" {
		return
	}
	if k < len(tail) && hourMeter.MatchString(tail[k]) {
		st["hourMeter"] = tail[k]
		k++
	} else if k < len(tail) && tail[k] == "" {
		k++
	}
	// analogue 1, analogue 2, backup battery %, device status
	rest := tail[k:]
	if len(rest) >= 4 {
		for a := 0; a < 2; a++ {
			v := rest[a]
			if strings.HasPrefix(v, "F") {
				if p, err := strconv.Atoi(v[1:]); err == nil {
					st[fmt.Sprintf("fuel%d", a+1)] = p
				}
			} else if mv, err := strconv.Atoi(v); err == nil {
				st[fmt.Sprintf("analog%d", a+1)] = float64(mv) / 1000
			}
		}
		if p, err := strconv.Atoi(rest[2]); err == nil && p >= 0 && p <= 100 {
			st["batteryLevel"] = p
		}
		deviceStatus(rest[3], st)
	} else if len(rest) >= 1 {
		// GL300 family: the battery percentage follows the mileage.
		if p, err := strconv.Atoi(rest[0]); err == nil && p >= 0 && p <= 100 {
			st["batteryLevel"] = p
		}
	}
}

// motionStates are the device's motion states (Device Status, GTSTT).
var motionStates = map[string]string{
	"16": "towed", "1A": "possiblyTowed", "11": "ignitionOffRest", "12": "ignitionOffMotion",
	"21": "ignitionOnRest", "22": "ignitionOnMotion", "41": "sensorRest", "42": "sensorMotion",
}

func motion(s string, st map[string]any) {
	s = strings.ToUpper(s)
	if m, ok := motionStates[s]; ok {
		st["motionState"] = m
		switch s[0] {
		case '1':
			st["ignition"] = false
		case '2':
			st["ignition"] = true
		}
		st["movement"] = s[1] == '2'
	}
}

// deviceStatus reads the 6 hex digits: motion state, inputs (bit 0
// ignition, bits 1-3 inputs 1-3), outputs (bits 0-2 outputs 1-3).
func deviceStatus(s string, st map[string]any) {
	if len(s) != 6 {
		return
	}
	motion(s[:2], st)
	in, e1 := strconv.ParseUint(s[2:4], 16, 8)
	out, e2 := strconv.ParseUint(s[4:6], 16, 8)
	if e1 == nil {
		st["ignition"] = in&1 == 1
		for b := 1; b <= 3; b++ {
			st[fmt.Sprintf("din%d", b)] = in>>b&1 == 1
		}
	}
	if e2 == nil {
		for b := 0; b < 3; b++ {
			st[fmt.Sprintf("dout%d", b+1)] = out>>b&1 == 1
		}
	}
}

// power reads the power fields of GTINF and GTBAT.
func power(present, vcc, battery, charging string, st map[string]any) {
	switch present {
	case "0":
		st["mainPower"] = false
	case "1":
		st["mainPower"] = true
	}
	if v, err := strconv.Atoi(vcc); err == nil {
		st["externalVoltage"] = float64(v) / 1000
	}
	if v, err := strconv.ParseFloat(battery, 64); err == nil {
		st["batteryVoltage"] = v
	}
	switch charging {
	case "0":
		st["charging"] = false
	case "1":
		st["charging"] = true
	}
}

// info reads +RESP:GTINF: state, ICCID, CSQ RSSI, CSQ BER, external power
// present, external VCC, reserved, backup battery V, charging, LED,
// reserved, GPS antenna, last fix time, pin 15 mode, analogue 1 and 2,
// digital inputs, digital outputs, time zone, daylight saving.
func info(f []string, st map[string]any) {
	if len(f) < 14 {
		return
	}
	motion(f[4], st)
	if f[5] != "" {
		st["iccid"] = f[5]
	}
	if v, err := strconv.Atoi(f[6]); err == nil && v != 99 {
		st["gsm"] = v
	}
	power(f[8], f[9], f[11], f[12], st)
	if len(f) >= 23 {
		if in, err := strconv.ParseUint(f[19], 16, 8); err == nil {
			st["ignition"] = in&1 == 1
			for b := 1; b <= 3; b++ {
				st[fmt.Sprintf("din%d", b)] = in>>b&1 == 1
			}
		}
		if out, err := strconv.ParseUint(f[20], 16, 8); err == nil {
			for b := 0; b < 3; b++ {
				st[fmt.Sprintf("dout%d", b+1)] = out>>b&1 == 1
			}
		}
	}
}

// ---- commands -------------------------------------------------------------

// serial is the command's serial number for sequence seq on this
// connection.
func (c *codec) serial(seq uint32) string {
	return fmt.Sprintf("%04X", (c.base+seq)&0xFFFF)
}

// Command frames a command without a device password (no password
// unless the profile has one).
func (c *codec) Command(imei string, content any, seq uint32) ([]byte, bool, error) {
	return c.CommandWithPassword(imei, "", content, seq)
}

// CommandWithPassword frames a command with the device's password
// (falling back to profile.password when it is ""). Every accepted
// command is acknowledged.
func (c *codec) CommandWithPassword(imei, password string, content any, seq uint32) ([]byte, bool, error) {
	n, named, err := track.ReadNamed(content)
	if err != nil {
		return nil, false, err
	}
	if named {
		pw := password
		if pw == "" {
			pw = c.cfg.password
		}
		if strings.ContainsAny(pw, ",$") {
			return nil, false, errors.New("the device's commandPassword must not contain ',' or '$'")
		}
		text, err := track.NamedText("queclink", n, c.cfg.named, defaultNamed, Interval, imei, pw)
		if err != nil {
			if strings.Contains(err.Error(), "needs the device's commandPassword") {
				return nil, false, fmt.Errorf("%w; set the device's commandPassword or profile.password (the factory password is the model name, such as gv300)", err)
			}
			return nil, false, err
		}
		return []byte(text + "," + c.serial(seq) + "$"), true, nil
	}
	text, err := track.CommandText(content)
	if err != nil {
		return nil, false, errors.New(`a command is {"text": "AT+GTxxx=<password>,…,<serial>$"} or {"action": …}`)
	}
	text = strings.TrimSpace(text)
	if !strings.HasPrefix(text, "AT+GT") || !strings.Contains(text, "=") {
		return nil, false, errors.New("a Queclink command starts with AT+GT and the command name, such as AT+GTRTO=")
	}
	body := strings.TrimSuffix(text, "$")
	if strings.ContainsAny(body, "$\r\n") {
		return nil, false, errors.New("a Queclink command holds one '$', at its end")
	}
	if len(body) > 400 {
		return nil, false, errors.New("a Queclink command is at most 400 characters")
	}
	return []byte(body + "$"), true, nil
}

var textSerial = regexp.MustCompile(`^AT\+(GT[A-Z0-9]{3})=.*,([0-9A-Fa-f]{4})\$?$`)

// Correlation: the acknowledgement names the command and carries its
// serial number. A raw text command is correlated by the serial it
// carries; one without a readable serial is not correlated.
func (c *codec) Correlation(content any, seq uint32) (string, bool) {
	if _, named, _ := track.ReadNamed(content); named {
		cmd := ""
		n, _, _ := track.ReadNamed(content)
		tmpl, _ := c.cfg.named.Template(n.Action, defaultNamed[n.Action])
		if len(tmpl) >= 10 {
			cmd = tmpl[3:8]
		}
		return cmd + "/" + c.serial(seq), true
	}
	text, err := track.CommandText(content)
	if err != nil {
		return "", false
	}
	if m := textSerial.FindStringSubmatch(strings.TrimSpace(text)); m != nil {
		return m[1] + "/" + strings.ToUpper(m[2]), true
	}
	return "", false
}
