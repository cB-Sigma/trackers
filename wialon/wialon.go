// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package wialon is Gurtam's Wialon IPS text tracker protocol, versions
// 1.1 and 2.0: packet reading, decoding into track.Message, and command
// framing. Our own implementation from Gurtam's public description
// ("Wialon IPS", v2.0 of 10/2014; it also covers what 1.1 sent, without
// the protocol version and checksums).
//
// Every packet is "#<type>#<text>\r\n"; a packet sent over UDP (and
// accepted over TCP too) starts with "<version>;<IMEI>" (2.0) or
// "<IMEI>" (1.1). Version 2.0 ends most packets with a CRC-16/ARC of the
// text, as four hex digits (CRC). Read from the device:
//
//	#L#2.0;<imei>;<password>;<crc>         login (1.1: #L#<imei>;<password>), answered #AL#1 (#AL#0 refused, #AL#10 bad CRC)
//	#SD#<date>;<time>;<lat>;N;<lon>;E;<speed>;<course>;<alt>;<sats>;<crc>   short data, answered #ASD#1
//	#D#<the SD fields>;<hdop>;<inputs>;<outputs>;<adc>;<ibutton>;<params>;<crc>   extended data, answered #AD#1
//	#B#<SD or D text>|<SD or D text>|…|<crc>   black box (history), answered #AB#<count>
//	#P#                                    ping, answered #AP#
//	#M#<text>;<crc>                        a driver's message or a command's answer, answered #AM#1
//	#I#<size>;<index>;<last>;<date>;<time>;<name>;<crc>\r\n<bytes>   picture block, answered #AI#<index>;1, the last #AI#1
//	#IT#<date>;<time>;<driver>;<code>;<blocks>;<crc>   tachograph (DDD) file information, answered #AIT#1
//	#T#<code>;<size>;<index>;<crc>\r\n<bytes>          tachograph file block, answered #AT#<index>;1, the last #AT#1
//
// A packet may come compressed: 0xFF, a little-endian 16-bit length and
// the packet deflated with zlib (Compress). Times are UTC (DDMMYY,
// HHMMSS); "NA" fields are absent, and a record without date and time
// takes the server's. A packet that cannot be read is answered with the
// protocol's error code for it (#AD#-1 structure, #AD#0 time, #AD#10
// coordinates, …) and passed over (track.Skip); one whose CRC does not
// match is answered with the CRC error code (#AL#10, #ASD#13, #AD#16,
// #AB#, #AM#01) and passed over with the warning crcMismatch, so the
// device sends it again.
//
// Status values: hdop goes into the fix; inputs and outputs (bit masks),
// adc1..adcN (the analogue inputs), driverId (the iButton) and every
// additional parameter under "params" (name → int64, float64 or string by
// its type 1, 2 or 3). The fixed parameters: SOS (1 is an emergency
// alert), text (a message for the driver chat, driverMessage) and
// mcc/mnc/lac/cell_id, optionally numbered (mcc1, mnc1, …), as cells. A
// picture becomes status image ([]byte) and imageName; a tachograph file
// ddd ([]byte), dddName and driverId.
//
// Commands:
//
//	{"text": "<custom command>"}     sent as "<text>\r\n"; the device answers with #M# (or a #D#)
//	{"message": "<text>"}            #M# to the driver's display; not answered
//	{"snapshot": true}               #QI#: the device sends a picture (#I#)
//	{"ddd": "<driver>"}              #QT#: the device sends the driver's tachograph file
//	{"firmware": "<base64>"}         #US#: firmware upload
//	{"configuration": "<base64>"}    #UC#: configuration file upload
//
// The protocol has no named commands (NamedActions is empty): a named
// command fails with track.ErrUnsupported unless the profile's
// namedCommands gives the device's custom command text, which is then
// sent as {"text"}. Answers name no command, so a late answer cannot be
// told from the next command's.
//
// The profile (NewCodec; Profile):
//
//	checkCrc: true                     # default true; false takes packets whose CRC does not match (with a warning)
//	params: {fuel: fuelLevel}          # an additional parameter → a status name of its own (none by default)
//	alarms: {door: door-open}          # an additional parameter → an alert type, raised when it is not 0 (none by default)
//	namedCommands: {locate: "getpos"}  # a named command's custom command text (none by default)
//	commandAnswers: true               # default true; false when the devices do not answer custom commands
//	version: "2.0"                     # the form of commands before the device's login names its version ("1.1" or "2.0")
//	failureWords: [error, unknown, invalid, failed, "not supported", incorrect]   # default; an answer holding one fails the command
package wialon

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/base64"
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

// Limits.
const (
	// MaxLine bounds one text packet (a black box packet carries up to
	// 5000 records).
	MaxLine = 4 << 20
	// MaxBlock bounds one picture or tachograph file block.
	MaxBlock = 1 << 20
	// MaxFile bounds a whole picture or tachograph file.
	MaxFile = 16 << 20
)

// Named commands.
var (
	// NamedActions are the named commands with a default text: none, the
	// protocol defines no such commands.
	NamedActions = []string{}
	// Interval bounds the interval command of a profile template.
	Interval = track.IntervalRange{Min: 1, Max: 86400}
)

// Profile is the manufacturer-variation settings.
type Profile struct {
	// CheckCRC (default true) refuses version 2.0 packets whose CRC does
	// not match with the protocol's CRC error answer.
	CheckCRC *bool `json:"checkCrc,omitempty"`
	// Params maps additional parameters to status names of their own.
	Params map[string]string `json:"params,omitempty"`
	// Alarms maps additional parameters to alert types, raised when the
	// parameter is not zero.
	Alarms map[string]string `json:"alarms,omitempty"`
	// NamedCommands gives named commands a custom command text, with
	// {seconds} and {imei}.
	NamedCommands track.NamedTemplates `json:"namedCommands,omitempty"`
	// CommandAnswers (default true) expects an answer to a custom command.
	CommandAnswers *bool `json:"commandAnswers,omitempty"`
	// Version is the protocol version commands are framed for until the
	// device's login names its own: "1.1" or "2.0" (default).
	Version string `json:"version,omitempty"`
	// FailureWords are the words whose presence in an answer fails the
	// command.
	FailureWords []string `json:"failureWords,omitempty"`
}

type config struct {
	crc     bool
	params  map[string]string
	alarms  map[string]string
	named   track.NamedTemplates
	answers bool
	v2      bool
	fail    []string
}

// NewCodec validates a profile (empty for the defaults) and returns a
// factory of codecs, one per connection.
func NewCodec(raw json.RawMessage) (func() track.Codec, error) {
	var p Profile
	if err := track.StrictJSON(raw, &p); err != nil {
		return nil, err
	}
	if err := p.NamedCommands.Check(false); err != nil {
		return nil, err
	}
	c := config{crc: p.CheckCRC == nil || *p.CheckCRC, params: p.Params, alarms: map[string]string{},
		named: p.NamedCommands, answers: p.CommandAnswers == nil || *p.CommandAnswers, v2: true}
	switch p.Version {
	case "", "2.0":
	case "1.1":
		c.v2 = false
	default:
		return nil, errors.New(`version is "1.1" or "2.0"`)
	}
	for k, v := range p.Params {
		if k == "" || v == "" {
			return nil, errors.New("params: map a parameter name to a status name")
		}
	}
	for k, v := range p.Alarms {
		if k == "" || v == "" {
			return nil, errors.New("alarms: map a parameter name to an alert type")
		}
		c.alarms[k] = v
	}
	fw, err := track.FailureWords(p.FailureWords, "error", "unknown", "invalid", "failed", "not supported", "incorrect")
	if err != nil {
		return nil, err
	}
	c.fail = fw
	return func() track.Codec { return &codec{cfg: c} }, nil
}

type codec struct {
	cfg     config
	imei    string
	version string // from the login or a UDP prefix; "" not known
	img     *file
	ddd     *file
}

// file is a picture or tachograph file being received.
type file struct {
	name, driver string
	at           time.Time
	data         []byte
	blocks       int // tachograph: the number of blocks
}

// ---- framing ----------------------------------------------------------------

// CRC is the protocol's CRC-16 (CRC-16/ARC: reflected 0x8005, initial
// value 0), sent as four hex digits.
func CRC(b []byte) uint16 { return track.CRC16IBM(b) }

// Compress builds a compressed packet: 0xFF, the length (little endian)
// and the packet deflated with zlib.
func Compress(packet []byte) []byte {
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	_, _ = w.Write(packet)
	_ = w.Close()
	out := []byte{0xFF}
	out = binary.LittleEndian.AppendUint16(out, uint16(z.Len()))
	return append(out, z.Bytes()...)
}

// Packet frames a text packet: "#<typ>#<text>" with the CRC of text
// appended when crc is set, then "\r\n". text should end with the
// separator that precedes the CRC (";" or "|").
func Packet(typ, text string, crc bool) []byte {
	s := "#" + typ + "#" + text
	if crc {
		s += fmt.Sprintf("%04X", CRC([]byte(text)))
	}
	return []byte(s + "\r\n")
}

// readLine reads up to '\n', bounded by MaxLine.
func readLine(r *bufio.Reader) ([]byte, error) {
	var out []byte
	for {
		b, err := r.ReadSlice('\n')
		out = append(out, b...)
		if len(out) > MaxLine {
			return nil, errors.New("wialon: packet too long")
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			if err == io.EOF && len(bytes.TrimSpace(out)) > 0 {
				return out, nil // a last packet without its line end
			}
			return nil, err
		}
		return out, nil
	}
}

// ---- decoding ---------------------------------------------------------------

func skip(code, msg, detail string, reply string) error {
	if len(detail) > 64 {
		detail = detail[:64]
	}
	s := &track.Skip{Warning: track.Warning{Code: code, Msg: msg, Detail: detail}}
	if reply != "" {
		s.Reply = []byte(reply)
	}
	return s
}

func (c *codec) Decode(r *bufio.Reader) (*track.Message, error) {
	first, err := r.Peek(1)
	if err != nil {
		return nil, err
	}
	if first[0] == 0xFF {
		return c.compressed(r)
	}
	line, err := readLine(r)
	if err != nil {
		return nil, err
	}
	return c.packet(string(bytes.TrimRight(line, "\r\n")), r)
}

func (c *codec) compressed(r *bufio.Reader) (*track.Message, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	z := make([]byte, binary.LittleEndian.Uint16(hdr[1:]))
	if _, err := io.ReadFull(r, z); err != nil {
		return nil, err
	}
	zr, err := zlib.NewReader(bytes.NewReader(z))
	if err != nil {
		return nil, skip("compressedUnreadable", "A compressed packet that could not be inflated was passed over.", err.Error(), "")
	}
	b, err := io.ReadAll(io.LimitReader(zr, MaxLine+1))
	if err != nil || len(b) > MaxLine {
		return nil, skip("compressedUnreadable", "A compressed packet that could not be inflated was passed over.", fmt.Sprint(err), "")
	}
	// The container holds one text packet; a picture or file block would
	// need its bytes, which follow the line inside the container.
	br := bufio.NewReader(bytes.NewReader(b))
	line, err := readLine(br)
	if err != nil {
		return nil, skip("compressedUnreadable", "A compressed packet without a text packet inside was passed over.", "", "")
	}
	return c.packet(string(bytes.TrimRight(line, "\r\n")), br)
}

var versionRe = regexp.MustCompile(`^\d+\.\d+$`)

// packet reads one text packet; r follows it (for binary blocks).
func (c *codec) packet(s string, r *bufio.Reader) (*track.Message, error) {
	if strings.TrimSpace(s) == "" {
		return nil, track.ErrSkip
	}
	if !strings.HasPrefix(s, "#") {
		i := strings.IndexByte(s, '#')
		if i <= 0 {
			return nil, skip("unknownMessage", "A message this codec does not read was passed over.", s, "")
		}
		pre := strings.Split(s[:i], ";")
		imei := pre[len(pre)-1]
		if len(pre) == 2 && versionRe.MatchString(pre[0]) {
			c.version = pre[0]
		}
		if imei != "" {
			c.imei = imei
		}
		s = s[i:]
	}
	j := strings.IndexByte(s[1:], '#')
	if j < 0 {
		return nil, skip("unknownMessage", "A message this codec does not read was passed over.", s, "")
	}
	typ, body := s[1:1+j], s[2+j:]
	var m *track.Message
	var err error
	switch typ {
	case "L":
		m, err = c.login(body)
	case "P":
		m = &track.Message{Kind: "health", Reply: []byte("#AP#\r\n")}
	case "SD", "D":
		m, err = c.data(typ, body)
	case "B":
		m, err = c.blackBox(body)
	case "M":
		m, err = c.message(body)
	case "I":
		m, err = c.image(body, r)
	case "IT":
		m, err = c.dddInfo(body)
	case "T":
		m, err = c.dddBlock(body, r)
	default:
		return nil, skip("unknownMessage", "A Wialon IPS packet of a type this codec does not read was passed over.", s, "")
	}
	if err != nil {
		return nil, err
	}
	if m.IMEI == "" {
		m.IMEI = c.imei
	}
	return m, nil
}

func (c *codec) v2() bool {
	if c.version == "" {
		return c.cfg.v2
	}
	return c.version != "1.1" && !strings.HasPrefix(c.version, "1.")
}

// isCRC reports whether s reads as a CRC field (hex, "0x" allowed).
func isCRC(s string) bool {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	if s == "" || len(s) > 4 {
		return false
	}
	_, err := strconv.ParseUint(s, 16, 16)
	return err == nil
}

func crcValue(s string) uint16 {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "0x"), "0X")
	v, _ := strconv.ParseUint(s, 16, 16)
	return uint16(v)
}

const crcMsg = "A packet whose CRC does not match was answered with the CRC error code (the device sends it again). Set profile.checkCrc to false if the device computes it another way."

// checkCRC checks covered against the CRC field; a mismatch is a Skip
// with errReply, or a warning when checkCrc is off.
func (c *codec) checkCRC(covered, field, errReply string) (*track.Warning, error) {
	if CRC([]byte(covered)) == crcValue(field) {
		return nil, nil
	}
	w := track.Warning{Code: "crcMismatch", Setting: "profile.checkCrc", Msg: crcMsg,
		Detail: fmt.Sprintf("CRC %s, computed %04X", field, CRC([]byte(covered)))}
	if c.cfg.crc {
		return nil, &track.Skip{Warning: w, Reply: []byte(errReply)}
	}
	return &w, nil
}

func (c *codec) login(body string) (*track.Message, error) {
	f := strings.Split(body, ";")
	var imei, pw string
	var warn *track.Warning
	switch {
	case len(f) >= 3 && versionRe.MatchString(f[0]):
		c.version = f[0]
		imei, pw = f[1], f[2]
		if len(f) >= 4 {
			cov := body[:len(body)-len(f[len(f)-1])]
			w, err := c.checkCRC(cov, f[len(f)-1], "#AL#10\r\n")
			if err != nil {
				return nil, err
			}
			warn = w
		}
	case len(f) == 2:
		c.version = "1.1"
		imei, pw = f[0], f[1]
	default:
		return nil, skip("badLogin", "A login packet that could not be read was refused.", body, "#AL#0\r\n")
	}
	if imei == "" {
		return nil, skip("badLogin", "A login packet without an IMEI was refused.", body, "#AL#0\r\n")
	}
	if pw == "NA" {
		pw = ""
	}
	c.imei = imei
	m := &track.Message{IMEI: imei, Login: true, Secret: pw, Kind: "login", Reply: []byte("#AL#1\r\n"), Reject: []byte("#AL#0\r\n")}
	if warn != nil {
		m.Warnings = append(m.Warnings, *warn)
	}
	return m, nil
}

// answer codes of SD and D packets.
const (
	codeStructure = "-1"
	codeTime      = "0"
	codeCoords    = "10"
	codeMotion    = "11"
	codeSats      = "12"
	codeIO        = "13"
	codeADC       = "14"
	codeParams    = "15"
)

type dataErr struct{ code, msg string }

func (e *dataErr) Error() string { return e.msg }

func (c *codec) data(typ, body string) (*track.Message, error) {
	f := strings.Split(body, ";")
	base := 10
	if typ == "D" {
		base = 16
	}
	crcCode := "#ASD#13\r\n"
	if typ == "D" {
		crcCode = "#AD#16\r\n"
	}
	var warn *track.Warning
	if len(f) == base+1 && isCRC(f[base]) {
		w, err := c.checkCRC(body[:len(body)-len(f[base])], f[base], crcCode)
		if err != nil {
			return nil, err
		}
		warn = w
		f = f[:base]
	}
	if len(f) != base {
		return nil, skip("badPacket", "A data packet that could not be read was answered with the structure error code.", body,
			"#A"+typ+"#"+codeStructure+"\r\n")
	}
	rec, err := c.record(f)
	if err != nil {
		var de *dataErr
		errors.As(err, &de)
		return nil, skip("badPacket", "A data packet with a field that could not be read was answered with its error code.", de.msg,
			"#A"+typ+"#"+de.code+"\r\n")
	}
	m := &track.Message{Kind: "normal", Records: []track.Record{rec}, Reply: []byte("#A" + typ + "#1\r\n")}
	if warn != nil {
		m.Warnings = append(m.Warnings, *warn)
	}
	setKind(m)
	return m, nil
}

func setKind(m *track.Message) {
	for _, r := range m.Records {
		for _, a := range r.Alerts {
			if a.Type == "emergency" {
				m.Kind = "emergency"
			}
		}
	}
}

func na(s string) bool { return s == "NA" || s == "" }

// num reads an optional number field.
func num(s string) (*float64, bool) {
	if na(s) {
		return nil, true
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
		return nil, false
	}
	return &v, true
}

// coord reads ddmm.mm / dddmm.mm with its hemisphere.
func coord(v, hemi string, neg string) (float64, bool, error) {
	if na(v) && na(hemi) {
		return 0, false, nil
	}
	x, err := strconv.ParseFloat(v, 64)
	if err != nil || x < 0 {
		return 0, false, &dataErr{codeCoords, "coordinate " + v}
	}
	deg := math.Floor(x / 100)
	d := deg + (x-deg*100)/60
	switch hemi {
	case neg:
		d = -d
	case "N", "E":
	default:
		return 0, false, &dataErr{codeCoords, "hemisphere " + hemi}
	}
	return d, true, nil
}

// record reads the fields of an SD (10) or D (16) packet.
func (c *codec) record(f []string) (track.Record, error) {
	rec := track.Record{Status: map[string]any{}}
	switch {
	case na(f[0]) && na(f[1]):
		rec.Time = time.Now().UTC()
	default:
		t, err := time.Parse("020106150405", f[0]+f[1])
		if err != nil {
			return rec, &dataErr{codeTime, "date and time " + f[0] + " " + f[1]}
		}
		rec.Time = t
	}
	lat, hasLat, err := coord(f[2], f[3], "S")
	if err != nil {
		return rec, err
	}
	lon, hasLon, err := coord(f[4], f[5], "W")
	if err != nil {
		return rec, err
	}
	if hasLat != hasLon || math.Abs(lat) > 90 || math.Abs(lon) > 180 {
		return rec, &dataErr{codeCoords, "coordinates"}
	}
	speed, ok1 := num(f[6])
	course, ok2 := num(f[7])
	alt, ok3 := num(f[8])
	if !ok1 || !ok2 || !ok3 {
		return rec, &dataErr{codeMotion, "speed, course or altitude"}
	}
	sats, ok := num(f[9])
	if !ok {
		return rec, &dataErr{codeSats, "satellites " + f[9]}
	}
	var hdop *float64
	if len(f) == 16 {
		if hdop, ok = num(f[10]); !ok {
			return rec, &dataErr{codeSats, "HDOP " + f[10]}
		}
		for i, name := range []string{"inputs", "outputs"} {
			v := f[11+i]
			if na(v) {
				continue
			}
			n, err := strconv.ParseInt(v, 10, 64)
			if err != nil {
				return rec, &dataErr{codeIO, name + " " + v}
			}
			rec.Status[name] = n
		}
		if !na(f[13]) {
			for i, a := range strings.Split(f[13], ",") {
				v, err := strconv.ParseFloat(strings.TrimSpace(a), 64)
				if err != nil {
					return rec, &dataErr{codeADC, "analogue input " + a}
				}
				rec.Status["adc"+strconv.Itoa(i+1)] = v
			}
		}
		if !na(f[14]) {
			rec.Status["driverId"] = f[14]
		}
		if !na(f[15]) {
			c.params(&rec, f[15])
		}
	}
	if hasLat {
		x := &track.Fix{Time: rec.Time, Lat: lat, Lon: lon, Speed: speed, Heading: course, Alt: alt, HDOP: hdop}
		x.Valid = true
		if sats != nil {
			n := int(*sats)
			x.Sats = &n
			x.Valid = n > 0
		}
		rec.Fix = x
	}
	return rec, nil
}

// params reads the additional parameters: name:type:value, separated by
// commas. A value that does not match its type is left out (as Wialon
// does) with a warning in the status (paramErrors).
func (c *codec) params(rec *track.Record, s string) {
	ps := map[string]any{}
	var bad []string
	cells := map[int]*track.Cell{}
	for _, item := range strings.Split(s, ",") {
		p := strings.SplitN(item, ":", 3)
		if len(p) != 3 || p[0] == "" {
			if strings.TrimSpace(item) != "" {
				bad = append(bad, item)
			}
			continue
		}
		name, typ, val := p[0], p[1], p[2]
		var v any
		switch typ {
		case "1":
			n, err := strconv.ParseInt(strings.TrimSpace(val), 10, 64)
			if err != nil {
				bad = append(bad, item)
				continue
			}
			v = n
		case "2":
			x, err := strconv.ParseFloat(strings.TrimSpace(val), 64)
			if err != nil {
				bad = append(bad, item)
				continue
			}
			v = x
		case "3":
			v = val
		default:
			bad = append(bad, item)
			continue
		}
		ps[name] = v
		if st, ok := c.cfg.params[name]; ok {
			rec.Status[st] = v
		}
		switch {
		case name == "SOS":
			if nonZero(v) {
				rec.Alerts = append(rec.Alerts, track.NewAlert("emergency", "SOS"))
			}
		case name == "text":
			rec.Status["driverMessage"] = fmt.Sprint(v)
		}
		if typ, ok := c.cfg.alarms[name]; ok && nonZero(v) {
			rec.Alerts = append(rec.Alerts, track.NewAlert(typ, name))
		}
		if n, ok := v.(int64); ok {
			cellParam(cells, name, n)
		}
	}
	rec.Status["params"] = ps
	if len(bad) > 0 {
		rec.Status["paramErrors"] = bad
	}
	var list []track.Cell
	for i := 0; i <= 16; i++ {
		if cl, ok := cells[i]; ok && cl.MCC != 0 && cl.CID != 0 {
			list = append(list, *cl)
		}
	}
	if len(list) > 0 {
		rec.Network = &track.Network{Cells: list}
	}
}

func nonZero(v any) bool {
	switch x := v.(type) {
	case int64:
		return x != 0
	case float64:
		return x != 0
	case string:
		s := strings.TrimSpace(strings.ToLower(x))
		return s != "" && s != "0" && s != "false"
	}
	return false
}

var cellRe = regexp.MustCompile(`^(mcc|mnc|lac|cell_id)(\d*)$`)

func cellParam(cells map[int]*track.Cell, name string, v int64) {
	m := cellRe.FindStringSubmatch(name)
	if m == nil {
		return
	}
	i := 0
	if m[2] != "" {
		i, _ = strconv.Atoi(m[2])
	}
	cl := cells[i]
	if cl == nil {
		cl = &track.Cell{}
		cells[i] = cl
	}
	switch m[1] {
	case "mcc":
		cl.MCC = int(v)
	case "mnc":
		cl.MNC = int(v)
	case "lac":
		cl.LAC = int(v)
	case "cell_id":
		cl.CID = v
	}
}

func (c *codec) blackBox(body string) (*track.Message, error) {
	items := strings.Split(body, "|")
	var warn *track.Warning
	last := items[len(items)-1]
	if len(items) > 1 && !strings.Contains(last, ";") && isCRC(last) {
		w, err := c.checkCRC(body[:len(body)-len(last)], last, "#AB#\r\n")
		if err != nil {
			return nil, err
		}
		warn = w
		items = items[:len(items)-1]
	}
	m := &track.Message{Kind: "normal"}
	var bad []track.Warning
	for _, it := range items {
		if it == "" {
			continue
		}
		f := strings.Split(it, ";")
		if len(f) != 10 && len(f) != 16 {
			bad = append(bad, track.Warning{Code: "badPacket", Detail: trim(it), Msg: "A black box record that could not be read was left out."})
			continue
		}
		rec, err := c.record(f)
		if err != nil {
			bad = append(bad, track.Warning{Code: "badPacket", Detail: err.Error(), Msg: "A black box record that could not be read was left out."})
			continue
		}
		rec.History = true
		m.Records = append(m.Records, rec)
	}
	m.Reply = []byte(fmt.Sprintf("#AB#%d\r\n", len(m.Records)))
	if warn != nil {
		m.Warnings = append(m.Warnings, *warn)
	}
	m.Warnings = append(m.Warnings, bad...)
	setKind(m)
	return m, nil
}

func trim(s string) string {
	if len(s) > 64 {
		return s[:64]
	}
	return s
}

func (c *codec) message(body string) (*track.Message, error) {
	text := body
	var warn *track.Warning
	if i := strings.LastIndexByte(body, ';'); i >= 0 && isCRC(body[i+1:]) {
		cov, field := body[:i+1], body[i+1:]
		// A 1.1 device's text may itself end in ";<hex>": the field is a
		// CRC when the device speaks 2.0 or when it matches.
		if c.v2() || CRC([]byte(cov)) == crcValue(field) {
			w, err := c.checkCRC(cov, field, "#AM#01\r\n")
			if err != nil {
				return nil, err
			}
			warn = w
			text = body[:i]
		}
	}
	m := &track.Message{Kind: "response", Response: &text, Failed: track.AnswerFailed(text, c.cfg.fail),
		Records: []track.Record{{Time: time.Now().UTC(), Status: map[string]any{"driverMessage": text}}},
		Reply:   []byte("#AM#1\r\n")}
	if warn != nil {
		m.Warnings = append(m.Warnings, *warn)
	}
	return m, nil
}

// block reads the binary block after a picture or file packet.
func block(r *bufio.Reader, size string) ([]byte, error) {
	n, err := strconv.Atoi(size)
	if err != nil || n < 0 || n > MaxBlock {
		return nil, fmt.Errorf("wialon: block size %q", size)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	return b, nil
}

func (c *codec) image(body string, r *bufio.Reader) (*track.Message, error) {
	f := strings.Split(body, ";")
	if len(f) < 6 {
		return nil, skip("badPacket", "A picture packet that could not be read was answered with the structure error code.", body, "#AI#NA;0\r\n")
	}
	// The block follows the line even when the fields are wrong; it is
	// read first so the stream stays in step.
	blk, err := block(r, f[0])
	if err != nil {
		return nil, err
	}
	ind, err1 := strconv.Atoi(f[1])
	last, err2 := strconv.Atoi(f[2])
	if err1 != nil || err2 != nil || ind < 0 || last < ind {
		return nil, skip("badPacket", "A picture packet that could not be read was answered with the structure error code.", body, "#AI#NA;0\r\n")
	}
	var warn *track.Warning
	if len(f) >= 7 {
		w, err := c.checkCRC(string(blk), f[6], fmt.Sprintf("#AI#%d;01\r\n", ind))
		if err != nil {
			return nil, err
		}
		warn = w
	}
	at, err := time.Parse("020106150405", f[3]+f[4])
	if err != nil {
		at = time.Now().UTC()
	}
	if ind == 0 || c.img == nil || c.img.name != f[5] {
		c.img = &file{name: f[5], at: at}
	}
	if len(c.img.data)+len(blk) > MaxFile {
		c.img = nil
		return nil, skip("fileTooLarge", "A picture larger than the codec takes was refused.", body, fmt.Sprintf("#AI#%d;0\r\n", ind))
	}
	c.img.data = append(c.img.data, blk...)
	m := &track.Message{Kind: "image", Reply: []byte(fmt.Sprintf("#AI#%d;1\r\n", ind))}
	if ind == last {
		img := c.img
		c.img = nil
		m.Reply = []byte("#AI#1\r\n")
		m.Records = []track.Record{{Time: img.at, Status: map[string]any{"image": img.data, "imageName": img.name}}}
	}
	if warn != nil {
		m.Warnings = append(m.Warnings, *warn)
	}
	return m, nil
}

func (c *codec) dddInfo(body string) (*track.Message, error) {
	f := strings.Split(body, ";")
	if len(f) < 5 {
		return nil, skip("badPacket", "A tachograph file information packet that could not be read was refused.", body, "#AIT#0\r\n")
	}
	var warn *track.Warning
	if len(f) >= 6 {
		w, err := c.checkCRC(body[:len(body)-len(f[len(f)-1])], f[len(f)-1], "#AIT#01\r\n")
		if err != nil {
			return nil, err
		}
		warn = w
	}
	at, err := time.Parse("020106150405", f[0]+f[1])
	n, err2 := strconv.Atoi(f[4])
	if err != nil || err2 != nil || n <= 0 || f[2] == "" {
		return nil, skip("badPacket", "A tachograph file information packet that could not be read was refused.", body, "#AIT#0\r\n")
	}
	c.ddd = &file{driver: f[2], at: at, blocks: n, name: f[2] + "_" + at.Format("20060102_150405") + ".ddd"}
	m := &track.Message{Kind: "file", Reply: []byte("#AIT#1\r\n")}
	if f[3] != "" {
		m.Warnings = append(m.Warnings, track.Warning{Code: "tachographError", Detail: f[3],
			Msg: "The device reported an error reading the tachograph file."})
	}
	if warn != nil {
		m.Warnings = append(m.Warnings, *warn)
	}
	return m, nil
}

func (c *codec) dddBlock(body string, r *bufio.Reader) (*track.Message, error) {
	f := strings.Split(body, ";")
	if len(f) < 3 {
		return nil, skip("badPacket", "A tachograph file block that could not be read was refused.", body, "#AT#NA;0\r\n")
	}
	blk, err := block(r, f[1])
	if err != nil {
		return nil, err
	}
	ind, err := strconv.Atoi(f[2])
	if err != nil || ind < 0 {
		return nil, skip("badPacket", "A tachograph file block that could not be read was refused.", body, "#AT#NA;0\r\n")
	}
	var warn *track.Warning
	if len(f) >= 4 {
		w, err := c.checkCRC(string(blk), f[3], fmt.Sprintf("#AT#%d;01\r\n", ind))
		if err != nil {
			return nil, err
		}
		warn = w
	}
	if c.ddd == nil {
		return nil, skip("badPacket", "A tachograph file block without its information packet was refused.", body, fmt.Sprintf("#AT#%d;0\r\n", ind))
	}
	if len(c.ddd.data)+len(blk) > MaxFile {
		c.ddd = nil
		return nil, skip("fileTooLarge", "A tachograph file larger than the codec takes was refused.", body, fmt.Sprintf("#AT#%d;0\r\n", ind))
	}
	c.ddd.data = append(c.ddd.data, blk...)
	m := &track.Message{Kind: "file", Reply: []byte(fmt.Sprintf("#AT#%d;1\r\n", ind))}
	if f[0] != "" {
		m.Warnings = append(m.Warnings, track.Warning{Code: "tachographError", Detail: f[0],
			Msg: "The device reported an error reading the tachograph file."})
	}
	if ind >= c.ddd.blocks-1 {
		d := c.ddd
		c.ddd = nil
		m.Reply = []byte("#AT#1\r\n")
		m.Records = []track.Record{{Time: d.at, Status: map[string]any{"ddd": d.data, "dddName": d.name, "driverId": d.driver}}}
	}
	if warn != nil {
		m.Warnings = append(m.Warnings, *warn)
	}
	return m, nil
}

// DecodeDatagram reads a UDP datagram: one or more packets, each with the
// "<version>;<IMEI>" (or 1.1 "<IMEI>") prefix, or compressed. A packet
// that is passed over becomes a message with only its warning and error
// answer.
func (c *codec) DecodeDatagram(b []byte) ([]*track.Message, error) {
	br := bufio.NewReader(bytes.NewReader(b))
	var out []*track.Message
	for {
		m, err := c.Decode(br)
		if err == io.EOF {
			break
		}
		var sk *track.Skip
		switch {
		case errors.As(err, &sk):
			out = append(out, &track.Message{IMEI: c.imei, Reply: sk.Reply, Warnings: []track.Warning{sk.Warning}})
		case errors.Is(err, track.ErrSkip):
		case err != nil:
			return out, err
		default:
			out = append(out, m)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("wialon: empty datagram")
	}
	return out, nil
}

// ---- commands ---------------------------------------------------------------

func (c *codec) Command(imei string, content any, _ uint32) ([]byte, bool, error) {
	if m, ok := content.(map[string]any); ok && len(m) == 1 {
		for k, v := range m {
			switch k {
			case "message":
				s, ok := v.(string)
				if !ok || s == "" {
					return nil, false, errors.New(`message is {"message": "<text for the driver>"}`)
				}
				if err := oneLine(s); err != nil {
					return nil, false, err
				}
				if c.v2() {
					return Packet("M", s+";", true), false, nil
				}
				return Packet("M", s, false), false, nil
			case "snapshot":
				if b, ok := v.(bool); !ok || !b {
					return nil, false, errors.New(`a picture request is {"snapshot": true}`)
				}
				return []byte("#QI#\r\n"), false, nil
			case "ddd":
				s, ok := v.(string)
				if !ok || s == "" || oneLine(s) != nil {
					return nil, false, errors.New(`a tachograph file request is {"ddd": "<driver>"}`)
				}
				return []byte("#QT#" + s + "\r\n"), false, nil
			case "firmware", "configuration":
				s, ok := v.(string)
				bin, err := base64.StdEncoding.DecodeString(s)
				if !ok || err != nil || len(bin) == 0 {
					return nil, false, fmt.Errorf(`%s is {"%s": "<base64 of the file>"}`, k, k)
				}
				typ := "US"
				if k == "configuration" {
					typ = "UC"
				}
				head := fmt.Sprintf("#%s#%d", typ, len(bin))
				if c.v2() {
					head += fmt.Sprintf(";%04X", CRC(bin))
				}
				return append([]byte(head+"\r\n"), bin...), false, nil
			}
		}
	}
	text, err := c.text(imei, content)
	if err != nil {
		return nil, false, err
	}
	if err := oneLine(text); err != nil {
		return nil, false, err
	}
	return []byte(text + "\r\n"), c.cfg.answers, nil
}

func oneLine(s string) error {
	if strings.ContainsAny(s, "\r\n") {
		return errors.New("a Wialon IPS command cannot contain a line break")
	}
	return nil
}

func (c *codec) text(imei string, content any) (string, error) {
	n, named, err := track.ReadNamed(content)
	if err != nil {
		return "", err
	}
	if !named {
		return track.CommandText(content)
	}
	if _, own := c.cfg.named[n.Action]; !own {
		return "", track.Unsupported("wialon", n.Action,
			"Wialon IPS defines no such command; set profile.namedCommands."+n.Action+" to the device's custom command text, or send it as text")
	}
	return track.NamedText("wialon", n, c.cfg.named, nil, Interval, imei, "")
}
