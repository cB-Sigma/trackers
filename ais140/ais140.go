// Package ais140 is the device protocol of AIS-140, ARAI's standard for
// vehicle location tracking devices in Indian public transport: packet
// reading, decoding into track.Message, OTA command framing (Table 4D)
// with checksums, OTA response correlation, and the unique device ID. Our
// own implementation: field lists are taken as facts from the standard's
// packet tables, and the parser is written to be tolerant because
// manufacturers differ in header layout, date form and checksum.
//
// Packets are comma-separated text from '$' to '*' (or end of line). Since
// Amendment 3 (04/2026) the standard fixes their sequence; those are read
// by position when their header and markers are in place (standard.go):
//
//   - login LGN (Table 4A(1)): vehicle, IMEI, ICCID, firmware, protocol
//     version, position;
//   - data PVT (Table 4A(2)): vendor, firmware, packet type, alert ID,
//     live/history, IMEI, vehicle, fix, date, time (UTC), position, speed,
//     heading, satellites, altitude, PDOP, HDOP, operator, ignition, main
//     power, voltages, emergency, tamper, GSM signal, serving cell, four
//     neighbour cells, digital inputs and outputs, frame number, analog
//     inputs, delta distance, OTA response and, on RFID trackers, the
//     trailer ID (3.1.1.28);
//   - health HLM (Table 3B): vendor, firmware, IMEI, battery %, low battery
//     threshold, memory %, update rates, digital I/O, analog inputs;
//   - emergency EPB (Table 4C i): EMR on or SEM off, IMEI, NM live or SP
//     stored, date-time, validity, position, altitude, speed, distance,
//     provider, vehicle, reply number; and its SMS form (Table 4C ii);
//   - ACTVR and HCHKR, the answers to activation and health check SMS
//     requests (Amendment 2, 8.4).
//
// Everything else, and packets whose markers are elsewhere (manufacturers
// kept their earlier layouts), is read by anchors: the latitude/longitude
// pair, the 15-digit IMEI, the packet type code, and a date that is
// DDMMYYYY, DDMMYY, split into six fields or joined with the time. A vendor
// the anchors cannot read gets an explicit layout (profile fields). After
// the cells, the digital inputs and outputs are found wherever the
// neighbour cells end, and what follows is read in the manufacturer's
// layout (VendorTails: RLP's frame number, odometer, analog input,
// accelerations and tilts; CTPL's frame number and odometer), picked from
// the packet or the profile, or else as the frame number and analog
// inputs. RLP devices' date and time before the fix flag are read too.
//
// The profile (NewCodec, ParseProfile; Profile):
//
//	layout: standard        # standard (default) | auto (anchors only)
//	checksum: ignore        # ignore (default) | xor (2 hex digits after '*', XOR of the characters between '$' and '*', or with the '$')
//	                        # | crc32 (last field: CRC-32/IEEE of the text from '$' through the comma before it)
//	fields: [header, vendor, firmware, packetType, alertId, packetStatus, imei, vehicle, gpsFix, date, time,
//	         lat, latDir, lon, lonDir, speed, heading, satellites, altitude, pdop, hdop, operator,
//	         ignition, mainPower, mainVoltage, batteryVoltage, emergency, tamper, gsm, mcc, mnc, lac, cellId]
//	alertIds: {"17": over-speed}      # alert ID → alert type (added to the defaults)
//	packetTypes: {"OS": over-speed}   # packet type → alert type (added to the defaults)
//	timezone: UTC                     # zone of the device's date and time (the standard says UTC)
//	acks: {login: "$LGN,OK*\r\n", normal: "", health: "", emergency: "$EPB,ACK,{imei}*\r\n"}   # templates, {imei} {frame}
//	commandFormat: standard           # standard (Table 4D) | text (older devices: commandTemplate)
//	otaPassword: "…"                  # command password of devices without their own
//	otaRole: P                        # P PVT server | E emergency server | PE (Table 4D allowed sources)
//	otaSources: ["vlt.example.in:5023", "+9198…"]   # sources a device may report; others raise ota-unknown-source
//	otaExtraIds: {"030": "SET,GET"}   # a manufacturer's own command IDs
//	commandTemplate: "{cmd}\r\n"      # text form only; {cmd} {imei}
//	commandAnswers: true              # wait for the device's answer
//	loginSecretField: 0               # field number (1 = the first after '$') of a login password (0: none)
//	healthFields: [batteryPercent, lowBatteryThreshold, memoryPercent, …]   # health packet fields after the IMEI
//	namedCommands: {engineStop: "@SET#RLP,OP1,"}   # a manufacturer's own line for a named command
//	vendor: ""                        # layout after the digital I/O: rlp | ctpl | standard ("" picks it from the packet)
//	tail: [frame, odometerKm, analogInput1]   # or name that layout's fields ("-" skips one)
//
// healthFields names, in order, the fields that follow the IMEI in a
// health (HLM) packet, for devices whose health packet differs from
// Table 3B. Each named field becomes a status value of that name (a
// number when it parses as one, except digitalIO and analogIO, which stay
// text; empty fields are left out). Without it the Table 3B order is used:
// batteryPercent, lowBatteryThreshold, memoryPercent,
// updateRateIgnitionOn, updateRateIgnitionOff, digitalIO, analogInput1,
// analogInput2.
//
// OTA commands (ota.go) are Table 4D commands with the device's password
// (track.PasswordCommander): {"op": "SET", "param": "009", "value": "80"}
// is sent as "$<IMEI>,<password>,SET,009:80*<checksum>", with the XOR
// checksum taken the way the device's own packets take it. The device
// answers with a data packet of alert ID 12 whose OTA response field
// lists each key's value and status; the codec is a track.Correlator, so
// that answer completes the command it names (its values in
// Message.Details), and a status 0 fails it. {"op": "HCHK"} and {"op":
// "ACTV"} are SMS requests (track.SMSRequester), which a server sends by
// SMS. With commandFormat text, {"op": "SET", "param": "SL", "value": "60"}
// is sent as "SET SL:60" and an answer with an OTA, ACK, SET, GET or CLR
// header, or a line without an IMEI, is the device's answer; ERR, FAIL or
// INVALID in it fails the command.
//
// ParseDeviceID checks the 19-character unique device ID of 3.1.1.12 (as
// amended), which no packet carries.
//
// References such as F-178 name source defects and ambiguities of the
// standard in SigmaM2M's register of specification defects; PROVENANCE.md
// describes each one.
package ais140

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cB-Sigma/trackers/track"
)

// Profile holds the manufacturer variations.
type Profile struct {
	Checksum         string            `json:"checksum,omitempty"`
	Fields           []string          `json:"fields,omitempty"`
	AlertIDs         map[string]string `json:"alertIds,omitempty"`
	PacketTypes      map[string]string `json:"packetTypes,omitempty"`
	Timezone         string            `json:"timezone,omitempty"`
	Acks             Acks              `json:"acks,omitempty"`
	CommandTemplate  string            `json:"commandTemplate,omitempty"`
	CommandAnswers   *bool             `json:"commandAnswers,omitempty"`
	LoginSecretField int               `json:"loginSecretField,omitempty"`
	HealthFields     []string          `json:"healthFields,omitempty"`
	// Layout "standard" (default) reads PVT, LGN, HLM and EPB packets in
	// the Amendment 3 tables' sequence when their markers are in place;
	// "auto" always reads by anchors.
	Layout string `json:"layout,omitempty"`
	// CommandFormat "standard" (default) frames Table 4D commands; "text"
	// sends commandTemplate with "SET <param>:<value>" (older devices).
	CommandFormat string `json:"commandFormat,omitempty"`
	// OTAPassword is the command password when a device has no
	// commandPassword of its own.
	OTAPassword string `json:"otaPassword,omitempty"`
	// OTARole is this backend's Table 4D source: P (PVT server, default),
	// E (emergency server) or both.
	OTARole string `json:"otaRole,omitempty"`
	// OTASources are the command sources a device may report in its OTA
	// responses (this server's host:port, the control centre numbers); a
	// response naming another raises ota-unknown-source. Empty: no check.
	OTASources []string `json:"otaSources,omitempty"`
	// OTAExtraIDs are a manufacturer's own command IDs: {"030": "SET,GET"}.
	OTAExtraIDs map[string]string `json:"otaExtraIds,omitempty"`
	// NamedCommands replaces the command line of a named command
	// (engineStop, engineResume, locate, reboot, interval) with a
	// manufacturer's own, sent as it is: {"engineStop": "@SET#RLP,OP1,"}.
	// Placeholders {seconds}, {password} and {imei}; "" turns one off.
	NamedCommands track.NamedTemplates `json:"namedCommands,omitempty"`
	// Vendor names a manufacturer's layout of the fields after the digital
	// inputs and outputs (VendorTails: rlp, ctpl) for packets read by
	// anchors; "" picks it from the packet (an RLP header, a CTPL vendor
	// ID) or reads the common frame number and analog inputs; "standard"
	// always reads those.
	Vendor string `json:"vendor,omitempty"`
	// Tail names the fields after the digital inputs and outputs in order
	// ("-" skips one): frame, analogInput1, analogInput2, deltaDistance,
	// odometerKm, accelX, accelY, accelZ, tiltX, tiltY. It overrides
	// vendor.
	Tail []string `json:"tail,omitempty"`
}

// VendorTails are the manufacturers' layouts of the fields after the
// digital inputs and outputs, longest first; the first that the packet has
// enough fields for is read. Layouts as Traccar's ITS decoder reads its
// published packets (facts only).
var VendorTails = map[string][][]string{
	// RLP firmware 2.1.3 adds an analog input, three accelerations and two
	// tilts to the frame number and odometer of 2.0.2 and 2.1.1.
	"rlp":  {{"frame", "odometerKm", "analogInput1", "accelX", "accelY", "accelZ", "tiltY", "tiltX"}, {"frame", "odometerKm"}},
	"ctpl": {{"frame", "odometerKm"}},
}

var tailNames = map[string]bool{"-": true, "frame": true, "analogInput1": true, "analogInput2": true, "deltaDistance": true,
	"odometerKm": true, "accelX": true, "accelY": true, "accelZ": true, "tiltX": true, "tiltY": true}

// Acks are reply templates per packet kind; empty sends nothing.
type Acks struct {
	Login     string `json:"login,omitempty"`
	Normal    string `json:"normal,omitempty"`
	Health    string `json:"health,omitempty"`
	Emergency string `json:"emergency,omitempty"`
}

// Default alert IDs of the standard's alert table (as facts), and packet
// type codes seen in the field.
var (
	DefaultAlertIDs = map[int]string{
		3: "main-power-removed", 4: "low-battery", 5: "low-battery-restored", 6: "main-power-restored",
		7: "ignition-on", 8: "ignition-off", 9: "box-opened", 10: "emergency", 11: "emergency-off",
		12: "ota-parameter-change", 13: "harsh-braking", 14: "harsh-acceleration", 15: "rash-turning",
		16: "emergency-wire-cut", 17: "over-speed", 22: "tilt", 23: "impact",
	}
	DefaultPacketTypes = map[string]string{
		"EA": "emergency", "TA": "tamper", "BD": "main-power-removed", "BR": "main-power-restored",
		"BL": "low-battery", "BC": "low-battery-restored", "BH": "low-battery-restored", "IN": "ignition-on", "IF": "ignition-off",
		"HB": "harsh-braking", "HA": "harsh-acceleration", "RT": "rash-turning", "DT": "emergency-wire-cut",
		"OA": "ota-parameter-change", "OS": "over-speed", "OTA": "ota-parameter-change", "TI": "tilt", "ACC": "impact",
	}
)

var fieldNames = map[string]bool{
	"-": true, "header": true, "vendor": true, "firmware": true, "packetType": true, "alertId": true, "packetStatus": true,
	"imei": true, "vehicle": true, "gpsFix": true, "date": true, "time": true, "datetime": true, "lat": true, "latDir": true,
	"lon": true, "lonDir": true, "speed": true, "heading": true, "satellites": true, "altitude": true, "pdop": true,
	"hdop": true, "operator": true, "ignition": true, "mainPower": true, "mainVoltage": true, "batteryVoltage": true,
	"emergency": true, "tamper": true, "gsm": true, "mcc": true, "mnc": true, "lac": true, "cellId": true, "frame": true,
}

// Config is a validated profile (ParseProfile).
type Config struct {
	named        track.NamedTemplates
	layout       string
	format       string
	otaPassword  string
	otaRole      string
	otaSources   []string
	otaExtra     map[string]OTAParam
	checksum     string
	fields       []string
	alertIDs     map[int]string
	packetTypes  map[string]string
	loc          *time.Location
	acks         Acks
	cmdTemplate  string
	answers      bool
	secretField  int
	healthFields []string
	vendor       string
	tail         []string
}

// NewCodec validates a profile (empty for the defaults) and returns a
// factory of codecs, one per connection.
func NewCodec(raw json.RawMessage) (func() track.Codec, error) {
	return NewCodecWith(raw, Options{})
}

// Options are what a server adds to a profile.
type Options struct {
	// CheckCommand, when set, sees every command frame before it is
	// returned; an error refuses the command ("OTA command refused: …").
	// A server checks firmware locations in vendor OTA text with it.
	CheckCommand func(frame []byte) error
}

// NewCodecWith is NewCodec with options.
func NewCodecWith(raw json.RawMessage, o Options) (func() track.Codec, error) {
	c, err := ParseProfile(raw)
	if err != nil {
		return nil, err
	}
	return func() track.Codec { return &codec{cfg: c, check: o.CheckCommand} }, nil
}

// SecretField is the field number of a login password (profile
// loginSecretField; 0 when logins carry none).
func (c *Config) SecretField() int { return c.secretField }

// NeedsCommandPassword reports whether Table 4D commands need a device
// password because the profile gives none (otaPassword) and commands are
// not in the older text form.
func (c *Config) NeedsCommandPassword() bool { return c.format != "text" && c.otaPassword == "" }

// ParseProfile validates a profile (empty for the defaults).
func ParseProfile(raw json.RawMessage) (*Config, error) {
	var p Profile
	if err := track.StrictJSON(raw, &p); err != nil {
		return nil, err
	}
	c := &Config{checksum: p.Checksum, fields: p.Fields, alertIDs: map[int]string{}, packetTypes: map[string]string{},
		loc: time.UTC, acks: p.Acks, cmdTemplate: p.CommandTemplate, answers: p.CommandAnswers == nil || *p.CommandAnswers,
		secretField: p.LoginSecretField, healthFields: p.HealthFields}
	if c.secretField < 0 {
		return nil, errors.New("loginSecretField must be 0 (none) or a field number")
	}
	switch c.checksum {
	case "":
		c.checksum = "ignore"
	case "ignore", "xor", "crc32":
	default:
		return nil, fmt.Errorf("checksum %q is not ignore, xor or crc32", c.checksum)
	}
	if len(c.fields) > 0 {
		seen := map[string]bool{}
		for _, f := range c.fields {
			if !fieldNames[f] {
				return nil, fmt.Errorf("fields: %q is not a known field name", f)
			}
			if f != "-" && seen[f] {
				return nil, fmt.Errorf("fields: %q appears twice", f)
			}
			seen[f] = true
		}
		for _, need := range []string{"imei", "lat", "lon"} {
			if !seen[need] {
				return nil, fmt.Errorf("fields must include %s", need)
			}
		}
	}
	for k, v := range DefaultAlertIDs {
		c.alertIDs[k] = v
	}
	for k, v := range p.AlertIDs {
		n, err := strconv.Atoi(k)
		if err != nil || v == "" {
			return nil, fmt.Errorf("alertIds: %q must map a number to an alert type", k)
		}
		c.alertIDs[n] = v
	}
	for k, v := range DefaultPacketTypes {
		c.packetTypes[k] = v
	}
	for k, v := range p.PacketTypes {
		if k == "" || v == "" {
			return nil, errors.New("packetTypes: codes and types must not be empty")
		}
		c.packetTypes[strings.ToUpper(k)] = v
	}
	if p.Timezone != "" {
		l, err := time.LoadLocation(p.Timezone)
		if err != nil {
			return nil, fmt.Errorf("timezone %q: %w", p.Timezone, err)
		}
		c.loc = l
	}
	if c.cmdTemplate == "" {
		c.cmdTemplate = "{cmd}\r\n"
	}
	if !strings.Contains(c.cmdTemplate, "{cmd}") {
		return nil, errors.New("commandTemplate must contain {cmd}")
	}
	if len(c.healthFields) == 0 {
		c.healthFields = stdHealthFields
	}
	switch c.layout = p.Layout; c.layout {
	case "":
		c.layout = "standard"
	case "standard", "auto":
	default:
		return nil, fmt.Errorf("layout %q is not standard or auto", p.Layout)
	}
	switch c.format = p.CommandFormat; c.format {
	case "":
		c.format = "standard"
		if p.CommandTemplate != "" {
			c.format = "text" // a template is the older devices' form
		}
	case "standard", "text":
	default:
		return nil, fmt.Errorf("commandFormat %q is not standard or text", p.CommandFormat)
	}
	c.otaPassword, c.otaSources = p.OTAPassword, p.OTASources
	if strings.ContainsAny(c.otaPassword, ",*$\r\n") {
		return nil, errors.New("otaPassword must not contain ',', '*', '$' or a line break")
	}
	c.otaRole = strings.ToUpper(p.OTARole)
	if c.otaRole == "" {
		c.otaRole = "P"
	}
	if strings.Trim(c.otaRole, "PE") != "" {
		return nil, fmt.Errorf("otaRole %q must be P (PVT server), E (emergency server) or PE", p.OTARole)
	}
	c.otaExtra = map[string]OTAParam{}
	for id, ops := range p.OTAExtraIDs {
		if len(id) != 3 || !isDigits(id) {
			return nil, fmt.Errorf("otaExtraIds: %q is not a three-digit command ID", id)
		}
		if _, ok := otaParam(id, nil); ok {
			return nil, fmt.Errorf("otaExtraIds: %s is a Table 4D ID already", id)
		}
		op := OTAParam{ID: id, Name: id, Sources: "PE"}
		for _, o := range strings.Split(strings.ToUpper(ops), ",") {
			switch strings.TrimSpace(o) {
			case "SET":
				op.Set = true
			case "GET":
				op.Get = true
			case "CLR":
				op.Clr = true
			default:
				return nil, fmt.Errorf("otaExtraIds.%s: %q is not SET, GET or CLR", id, o)
			}
		}
		c.otaExtra[id] = op
	}
	if err := p.NamedCommands.Check(true); err != nil {
		return nil, err
	}
	c.named = p.NamedCommands
	if _, ok := VendorTails[p.Vendor]; !ok && p.Vendor != "" && p.Vendor != "standard" {
		return nil, fmt.Errorf("vendor %q is not one of rlp, ctpl or standard", p.Vendor)
	}
	c.vendor = p.Vendor
	seen := map[string]bool{}
	for _, f := range p.Tail {
		if !tailNames[f] {
			return nil, fmt.Errorf("tail: %q is not a known field name", f)
		}
		if f != "-" && seen[f] {
			return nil, fmt.Errorf("tail: %q appears twice", f)
		}
		seen[f] = true
	}
	c.tail = p.Tail
	return c, nil
}

type codec struct {
	cfg   *Config
	check func([]byte) error
	imei  string
	// sumDollar: the device's XOR checksums include the '$' (seen on a
	// packet it sent); commands to it are framed the same way.
	sumDollar bool
}

// ---- framing ----------------------------------------------------------------

const maxFrame = 2048

// ErrChecksum is a packet whose checksum does not match.
var ErrChecksum = errors.New("ais140: checksum mismatch")

// readFrame returns the text of one packet: from '$' (or the first
// printable byte of a line) to '*', the end of the line or the next '$',
// and the checksum digits after '*', if any.
func readFrame(r *bufio.Reader, waitChecksum bool) (text, sum string, err error) {
	// Skip separators and any trailing text after a '*' (seen in the field).
	for {
		b, err := r.ReadByte()
		if err != nil {
			return "", "", err
		}
		if b == '$' || (b > ' ' && b != '*' && b != ',') {
			_ = r.UnreadByte()
			break
		}
	}
	var sb strings.Builder
	for {
		if sb.Len() > maxFrame {
			return "", "", errors.New("ais140: packet too long")
		}
		b, err := r.ReadByte()
		if err != nil {
			if sb.Len() > 0 && errors.Is(err, io.EOF) {
				return sb.String(), "", nil
			}
			return "", "", err
		}
		switch {
		case b == '$' && sb.Len() > 0:
			_ = r.UnreadByte()
			return sb.String(), "", nil
		case b == '\r' || b == '\n':
			return sb.String(), "", nil
		case b == '*':
			var cs strings.Builder
			for cs.Len() < 8 {
				if !waitChecksum && r.Buffered() == 0 {
					break
				}
				nb, err := r.Peek(1)
				if err != nil || !isHex(nb[0]) {
					break
				}
				_, _ = r.ReadByte()
				cs.WriteByte(nb[0])
				if waitChecksum && cs.Len() == 2 {
					break
				}
			}
			return sb.String(), cs.String(), nil
		default:
			sb.WriteByte(b)
		}
	}
}

func isHex(b byte) bool {
	return b >= '0' && b <= '9' || b >= 'a' && b <= 'f' || b >= 'A' && b <= 'F'
}

// ---- decoding ---------------------------------------------------------------

func (c *codec) Decode(r *bufio.Reader) (*track.Message, error) {
	text, sum, err := readFrame(r, c.cfg.checksum == "xor")
	if err != nil {
		return nil, err
	}
	if with, ok := xorForm(text, sum); ok {
		c.sumDollar = with
	}
	m, err := c.cfg.Parse(text, sum)
	if errors.Is(err, ErrChecksum) {
		return nil, &track.Skip{Warning: track.Warning{Code: "checksumMismatch", Setting: "profile.checksum", Detail: sum,
			Msg: "A packet whose checksum does not match was dropped (profile.checksum is " + c.cfg.checksum + "). Set profile.checksum to ignore if the device computes it another way."}}
	}
	if errors.Is(err, errNothing) {
		return nil, track.ErrSkip
	}
	if err != nil {
		return nil, err
	}
	if m.IMEI == "" {
		m.IMEI = c.imei
	} else if c.imei == "" {
		c.imei = m.IMEI
	}
	// For forwarding: the packet re-framed as the standard frames it, from
	// '$' to '*' and its checksum digits, ended by CR LF.
	m.Raw = []byte(text + "*" + sum + "\r\n")
	return m, nil
}

var errNothing = errors.New("ais140: nothing to read")

// Kinds of packet.
const (
	KLogin     = "login"
	KNormal    = "normal"
	KHealth    = "health"
	KEmergency = "emergency"
	KResponse  = "response"
	// KCheck is an activation or health check answer (ACTVR, HCHKR).
	KCheck = "check"
)

var replyHeaders = map[string]bool{"OTA": true, "ACK": true, "CMD": true, "RSP": true, "RES": true}

// Parse reads one packet's text (without '*' and what follows) and its
// checksum digits.
func (c *Config) Parse(text, sum string) (*track.Message, error) {
	if strings.TrimSpace(text) == "" {
		return nil, errNothing
	}
	dollar := strings.HasPrefix(text, "$")
	if err := c.verify(text, sum); err != nil {
		return nil, err
	}
	tok := strings.Split(strings.TrimPrefix(text, "$"), ",")
	if c.checksum == "crc32" && len(tok) > 1 {
		tok = tok[:len(tok)-1]
	}
	for i := range tok {
		tok[i] = strings.TrimSpace(tok[i])
	}
	kind, p := c.classify(tok, dollar)
	switch kind {
	case "":
		return nil, errNothing
	case KResponse:
		t := strings.TrimSpace(strings.TrimPrefix(text, "$"))
		up := strings.ToUpper(t)
		return &track.Message{Kind: KResponse, Response: &t, Failed: strings.Contains(up, "ERR") || strings.Contains(up, "FAIL") || strings.Contains(up, "INVALID")}, nil
	}
	m, err := c.build(kind, p)
	if m != nil {
		m.Kind = kind
		if kind == KCheck {
			m.Kind = KHealth
		}
	}
	return m, err
}

// nonEmptyFrom drops the empty fields before the header ("$,EPB,…").
func nonEmptyFrom(tok []string) []string {
	for i, t := range tok {
		if t != "" {
			return tok[i:]
		}
	}
	return nil
}

func (c *Config) verify(text, sum string) error {
	switch c.checksum {
	case "xor":
		// Item 18 of Amendment 3 XORs "the data" without saying where it
		// starts (F-179): the characters between '$' and '*', or with the
		// '$'. Either is accepted.
		var x byte
		for i := 1; i < len(text); i++ {
			x ^= text[i]
		}
		if !strings.EqualFold(fmt.Sprintf("%02X", x), sum) && !strings.EqualFold(fmt.Sprintf("%02X", x^'$'), sum) {
			return ErrChecksum
		}
	case "crc32":
		i := strings.LastIndexByte(strings.TrimRight(text, ","), ',')
		if i < 0 {
			return ErrChecksum
		}
		want := strings.TrimRight(text[i+1:], ",")
		if !strings.EqualFold(fmt.Sprintf("%08X", crc32.ChecksumIEEE([]byte(text[:i+1]))), want) {
			return ErrChecksum
		}
	}
	return nil
}

func upper(s string) string { return strings.ToUpper(s) }

// classify names the packet kind and its fields.
func (c *Config) classify(tok []string, dollar bool) (string, map[string]string) {
	head := ""
	var first []string
	for _, t := range tok {
		if t != "" && len(first) < 3 {
			first = append(first, upper(t))
		}
	}
	if len(first) > 0 {
		head = first[0]
	}
	imei := findIMEI(tok, len(tok))
	// Activation and health check answers (Amendment 2, 8.4 Table-1), by
	// SMS (no '$') or over the connection.
	if head == "ACTVR" || head == "HCHKR" {
		if p, ok := stdCheckReply(nonEmptyFrom(tok)); ok {
			return KCheck, p
		}
	}
	if !dollar {
		if len(head) >= 2 && strings.ContainsAny(head[:1], "ABCDEFGHIJKLMNOPQRSTUVWXYZ") &&
			(strings.HasPrefix(head, "SET") || strings.HasPrefix(head, "GET") || strings.HasPrefix(head, "CLR") ||
				strings.HasPrefix(head, "OTA") || strings.HasPrefix(head, "ACK") || strings.HasPrefix(head, "OK") || strings.HasPrefix(head, "ERR")) {
			return KResponse, nil
		}
		return "", nil
	}
	if replyHeaders[head] || strings.HasPrefix(head, "SET ") || strings.HasPrefix(head, "GET ") || strings.HasPrefix(head, "CLR ") {
		return KResponse, nil
	}
	// The Amendment 3 tables, by their header, when the markers are in
	// place.
	if c.layout == "standard" && len(c.fields) == 0 {
		switch std := nonEmptyFrom(tok); head {
		case "PVT":
			if p, ok := pvt(std); ok {
				return KNormal, p
			}
		case "LGN":
			if p, ok := stdLogin(std); ok {
				if c.secretField > 0 {
					p["secret"] = at(tok, c.secretField-1)
				}
				return KLogin, p
			}
		case "HLM":
			if len(std) > 4 && imeiField(std[3]) {
				p := c.health(std, 3)
				p["vendor"], p["firmware"] = std[1], std[2]
				return KHealth, p
			}
		}
	}
	for _, f := range first {
		if f == "EPB" || f == "EMR" || f == "SEM" {
			if a, im := anchor(tok), findIMEI(tok, len(tok)); a >= 0 && im >= 0 && a == im+1 {
				return KEmergency, stdEmergencySMS(tok, im, a)
			}
			return KEmergency, c.auto(tok, KEmergency)
		}
	}
	for _, f := range first {
		if f == "LGN" || f == "LOGIN" {
			return KLogin, c.login(tok)
		}
		if f == "HLM" || f == "HP" || f == "HBT" || f == "HEALTH" {
			return KHealth, c.health(tok, imei)
		}
	}
	if imei < 0 {
		return KResponse, nil
	}
	if a := anchor(tok); a < 0 {
		if len(tok)-imei-1 >= 4 {
			return KHealth, c.health(tok, imei)
		}
		return KLogin, c.login(tok)
	}
	if len(c.fields) > 0 {
		return KNormal, c.explicit(tok)
	}
	p := c.auto(tok, KNormal)
	if p["date"] == "" && p["datetime"] == "" {
		return KLogin, c.login(tok)
	}
	return KNormal, p
}

func isDigits(s string) bool {
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

func findIMEI(tok []string, end int) int {
	// A 15-digit IMEI first; then the IMEISV (16) and a 17-digit form with
	// a leading zero, which devices are seen to send; the 14-digit IMEI
	// without its check digit only before the position (end bounds the
	// search), since a DDMMYYYYhhmmss date-time also has 14 digits.
	lengths := []int{15, 16, 17}
	if end < len(tok) {
		lengths = append(lengths, 14)
	}
	for _, n := range lengths {
		for i := 0; i < end && i < len(tok); i++ {
			if len(tok[i]) == n && isDigits(tok[i]) {
				return i
			}
		}
	}
	return -1
}

// imeiField reports whether s can be the IMEI field of a fixed layout:
// 14 to 17 digits (15 is the standard's).
func imeiField(s string) bool { return len(s) >= 14 && len(s) <= 17 && isDigits(s) }

func isFloat(s string) bool {
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}

// anchor finds the latitude field: a number followed by N or S, a number
// and E or W.
func anchor(tok []string) int {
	for i := 0; i+3 < len(tok); i++ {
		if (tok[i+1] == "N" || tok[i+1] == "S") && (tok[i+3] == "E" || tok[i+3] == "W") && isFloat(tok[i]) && isFloat(tok[i+2]) {
			return i
		}
	}
	return -1
}

func at(tok []string, i int) string {
	if i < 0 || i >= len(tok) {
		return ""
	}
	return tok[i]
}

// auto reads a normal or emergency packet by its anchors.
func (c *Config) auto(tok []string, kind string) map[string]string {
	p := map[string]string{}
	a := anchor(tok)
	im := findIMEI(tok, max(a, 0))
	if im < 0 {
		im = findIMEI(tok, len(tok))
	}
	p["imei"] = at(tok, im)
	if a < 0 {
		return p
	}
	p["lat"], p["latDir"], p["lon"], p["lonDir"] = tok[a], tok[a+1], tok[a+2], tok[a+3]
	// Packet type, alert ID and live/history status before the IMEI.
	for i := 0; i < im; i++ {
		t := upper(tok[i])
		if _, ok := c.packetTypes[t]; ok || t == "NR" || t == "HP" || t == "EMR" || t == "SEM" {
			if p["packetType"] != "" && kind == KEmergency {
				continue
			}
			p["packetType"] = t
			for j := i + 1; j <= i+2 && j < im; j++ {
				switch u := upper(tok[j]); {
				case isDigits(u) && p["alertId"] == "":
					p["alertId"] = u
				case u == "L" || u == "H" || u == "NM" || u == "SP":
					p["packetStatus"] = u
				}
			}
		}
	}
	if p["packetType"] == "" && kind == KNormal {
		// An unknown code: two or three capitals, then a number and L or H.
		for i := 0; i+2 < im; i++ {
			t, st := tok[i], upper(tok[i+2])
			if len(t) >= 2 && len(t) <= 3 && t == upper(t) && !isDigits(t) && isDigits(tok[i+1]) && (st == "L" || st == "H") {
				p["packetType"], p["alertId"], p["packetStatus"] = t, tok[i+1], st
				break
			}
		}
	}
	if kind == KEmergency {
		// IMEI, NM|SP, date-time, A|V, position, altitude, speed, distance, provider, vehicle, reply number.
		if s := upper(at(tok, im+1)); s == "NM" || s == "SP" {
			p["packetStatus"] = s
		}
		p["gpsFix"] = at(tok, a-1)
		switch d := at(tok, a-2); {
		case len(d) == 14 && isDigits(d):
			p["datetime"] = d
		case len(d) == 6 && isDigits(d):
			p["time"], p["date"] = d, at(tok, a-3)
		}
		e := a + 4
		p["altitude"], p["speed"], p["vehicle"] = at(tok, e), at(tok, e+1), at(tok, e+4)
		p["deltaDistance"], p["provider"], p["replyNumber"] = at(tok, e+2), at(tok, e+3), at(tok, e+5)
		return p
	}
	if im >= 0 && im+1 < a {
		p["vehicle"] = tok[im+1]
	}
	switch {
	case len(at(tok, a-1)) == 6 && isDigits(at(tok, a-1)) && (len(at(tok, a-2)) == 8 || len(at(tok, a-2)) == 6) && isDigits(at(tok, a-2)):
		p["time"], p["date"], p["gpsFix"] = tok[a-1], tok[a-2], at(tok, a-3)
	case a >= 7 && len(tok[a-4]) == 4 && isDigits(tok[a-4]) && len(tok[a-6]) == 2 && isDigits(tok[a-6]) && isDigits(tok[a-1]):
		p["date"] = tok[a-6] + tok[a-5] + tok[a-4]
		p["time"] = tok[a-3] + tok[a-2] + tok[a-1]
		p["gpsFix"] = at(tok, a-7)
	case fixFlag(at(tok, a-1)) && len(at(tok, a-2)) == 6 && isDigits(at(tok, a-2)) && (len(at(tok, a-3)) == 8 || len(at(tok, a-3)) == 6) && isDigits(at(tok, a-3)):
		// The date and time before the fix flag (RLP).
		p["date"], p["time"], p["gpsFix"] = tok[a-3], tok[a-2], tok[a-1]
	}
	e := a + 4
	names := []string{"speed", "heading", "satellites", "altitude", "pdop", "hdop", "operator", "ignition", "mainPower", "mainVoltage", "batteryVoltage", "emergency"}
	for i, n := range names {
		p[n] = at(tok, e+i)
	}
	e += len(names)
	if t := at(tok, e); !isFloat(t) && e < len(tok) {
		p["tamper"] = t
		e++
	}
	for i, n := range []string{"gsm", "mcc", "mnc", "lac", "cellId"} {
		p[n] = at(tok, e+i)
	}
	c.tailFields(tok, e+5, p)
	return p
}

func fixFlag(s string) bool { return s == "0" || s == "1" || s == "A" || s == "V" }

// tailFields reads what follows the cells: the digital inputs (four of 0,
// 1 or 2) and outputs (two of 0 or 1), wherever the neighbour cells end,
// then the vendor's layout (profile tail, vendor, or one picked from the
// packet), or else the frame number and analog inputs when they are
// recognisable.
func (c *Config) tailFields(tok []string, from int, p map[string]string) {
	j := -1
	for i := from; i+1 < len(tok); i++ {
		if len(tok[i]) == 4 && strings.Trim(tok[i], "012") == "" && len(tok[i+1]) == 2 && strings.Trim(tok[i+1], "01") == "" {
			j = i
			break
		}
	}
	if j < 0 {
		return
	}
	p["digitalInputs"], p["digitalOutputs"] = tok[j], tok[j+1]
	rest := tok[j+2:]
	for len(rest) > 0 && rest[len(rest)-1] == "" {
		rest = rest[:len(rest)-1]
	}
	layout := c.tail
	if layout == nil {
		v := c.vendor
		if v == "" {
			v = vendorOf(tok)
		}
		for _, l := range VendorTails[v] {
			if len(rest) >= len(l) {
				layout = l
				break
			}
		}
	}
	if layout == nil {
		switch {
		case len(rest) > 0 && len(rest[0]) >= 5 && isDigits(rest[0]):
			layout = []string{"frame", "analogInput1", "analogInput2", "deltaDistance"}
		case len(rest) > 2 && strings.Contains(rest[0], ".") && strings.Contains(rest[1], ".") && isFloat(rest[0]) && isFloat(rest[1]) &&
			len(rest[2]) >= 5 && isDigits(rest[2]):
			layout = []string{"analogInput1", "analogInput2", "frame"}
		}
	}
	for i, n := range layout {
		if n != "-" && i < len(rest) {
			p[n] = rest[i]
		}
	}
}

// vendorOf picks a vendor layout from the packet: an RLP header or a CTPL
// vendor ID.
func vendorOf(tok []string) string {
	for i, t := range tok {
		if i > 3 {
			break
		}
		switch upper(t) {
		case "RLP":
			if i == 0 {
				return "rlp"
			}
		case "CTPL":
			return "ctpl"
		}
	}
	return ""
}

// explicit reads a normal packet by the configured layout.
func (c *Config) explicit(tok []string) map[string]string {
	p := map[string]string{}
	for i, n := range c.fields {
		if n != "-" {
			p[n] = at(tok, i)
		}
	}
	return p
}

func (c *Config) login(tok []string) map[string]string {
	p := map[string]string{}
	im := findIMEI(tok, len(tok))
	p["imei"] = at(tok, im)
	if a := anchor(tok); a >= 0 {
		p["lat"], p["latDir"], p["lon"], p["lonDir"] = tok[a], tok[a+1], tok[a+2], tok[a+3]
	}
	// The vehicle registration sits next to the IMEI; pick the neighbour
	// that looks like one (letters and digits, not a version).
	for _, i := range []int{im - 1, im + 1} {
		if v := at(tok, i); looksLikeReg(v) {
			p["vehicle"] = v
			break
		}
	}
	if c.secretField > 0 {
		p["secret"] = at(tok, c.secretField-1)
	}
	return p
}

func looksLikeReg(s string) bool {
	if len(s) < 6 || len(s) > 12 || strings.ContainsAny(s, "._") {
		return false
	}
	letters, digits := 0, 0
	for i := 0; i < len(s); i++ {
		switch b := s[i]; {
		case b >= '0' && b <= '9':
			digits++
		case b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z':
			letters++
		default:
			return false
		}
	}
	return letters >= 2 && digits >= 1
}

func (c *Config) health(tok []string, im int) map[string]string {
	p := map[string]string{"imei": at(tok, im)}
	for i, n := range c.healthFields {
		p["h:"+n] = at(tok, im+1+i)
	}
	return p
}

// ---- building messages ------------------------------------------------------

func num(s string) (float64, bool) {
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return v, err == nil && !math.IsNaN(v) && !math.IsInf(v, 0)
}

func (c *Config) when(p map[string]string) time.Time {
	d, t := p["date"], p["time"]
	if dt := p["datetime"]; len(dt) == 14 {
		d, t = dt[:8], dt[8:]
	}
	var layout string
	switch len(d) {
	case 8:
		layout = "02012006150405"
	case 6:
		layout = "020106150405"
	default:
		return time.Time{}
	}
	if len(t) != 6 {
		return time.Time{}
	}
	v, err := time.ParseInLocation(layout, d+t, c.loc)
	if err != nil {
		return time.Time{}
	}
	return v.UTC()
}

func (c *Config) fix(p map[string]string) *track.Fix {
	lat, ok1 := num(p["lat"])
	lon, ok2 := num(p["lon"])
	if !ok1 || !ok2 {
		return nil
	}
	if p["latDir"] == "S" {
		lat = -lat
	}
	if p["lonDir"] == "W" {
		lon = -lon
	}
	f := &track.Fix{Lat: lat, Lon: lon, Time: c.when(p)}
	switch upper(p["gpsFix"]) {
	case "0", "V":
	default:
		f.Valid = lat != 0 || lon != 0
	}
	for k, dst := range map[string]**float64{"speed": &f.Speed, "heading": &f.Heading, "altitude": &f.Alt, "hdop": &f.HDOP} {
		if v, ok := num(p[k]); ok {
			*dst = track.F(v)
		}
	}
	if v, ok := num(p["satellites"]); ok {
		f.Sats = track.I(int(v))
	}
	return f
}

func boolish(s string) (bool, bool) {
	switch s {
	case "1":
		return true, true
	case "0":
		return false, true
	}
	return false, false
}

func (c *Config) build(kind string, p map[string]string) (*track.Message, error) {
	m := &track.Message{IMEI: p["imei"]}
	if m.IMEI != "" && isDigits(m.IMEI) && len(m.IMEI) != 15 {
		m.Warnings = append(m.Warnings, track.Warning{Code: "imeiLength", Setting: "devices[].imei", Detail: m.IMEI,
			Msg: "The packet's IMEI does not have the 15 digits of AIS-140; it is accepted (a listed device is matched by its other IMEI forms)."})
	}
	if m.IMEI != "" && !isDigits(m.IMEI) {
		// Kept: the server decides whether it names a device (listed or
		// allowUnknown) and warns about its form.
		m.Warnings = append(m.Warnings, track.Warning{Code: "imeiFormat", Setting: "devices[].imei", Detail: m.IMEI,
			Msg: "The packet's IMEI is not all digits; it is accepted as written."})
	}
	rec := track.Record{Status: map[string]any{}}
	for _, k := range []string{"vendor", "firmware"} {
		if v := p[k]; v != "" {
			rec.Status[k] = v
		}
	}
	switch kind {
	case KLogin:
		m.Login, m.Secret, m.ICCID = true, p["secret"], p["iccid"]
		if f := c.fix(p); f != nil && (f.Lat != 0 || f.Lon != 0) {
			// A login position has no time; keep it as status, not as a fix.
			rec.Status["loginLat"], rec.Status["loginLon"] = f.Lat, f.Lon
		}
		if v := p["iccid"]; v != "" {
			rec.Status["iccid"] = v
		}
		if v := p["protocol"]; v != "" {
			rec.Status["protocolVersion"] = v
		}
		m.Reply = c.ack(c.acks.Login, p)
	case KHealth:
		for _, n := range c.healthFields {
			v := p["h:"+n]
			if f, ok := num(v); ok && n != "digitalIO" && n != "analogIO" {
				rec.Status[n] = f
			} else if v != "" {
				rec.Status[n] = v
			}
		}
		m.Reply = c.ack(c.acks.Health, p)
	case KCheck:
		// An answer to an SMS request: a live position and status.
		rec.Fix = c.fix(p)
		if rec.Fix != nil {
			rec.Time = rec.Fix.Time
		}
		c.status(p, rec.Status)
		m.ReplyKind, m.ReplyCode = p["replyKind"], p["replyCode"]
		m.Details = map[string]any{"imei": p["imei"], "firmware": p["firmware"], "alertId": p["alertId"], "vehicleMode": p["vehicleMode"]}
		if rec.Fix != nil {
			m.Details["lat"], m.Details["lon"], m.Details["fix"] = rec.Fix.Lat, rec.Fix.Lon, rec.Fix.Valid
		}
	case KNormal, KEmergency:
		rec.Fix = c.fix(p)
		if rec.Fix != nil {
			rec.Time = rec.Fix.Time
		}
		st := upper(p["packetStatus"])
		rec.History = st == "H" || st == "SP" || (st == "" && strings.TrimLeft(p["alertId"], "0") == "2")
		c.status(p, rec.Status)
		if a := c.alert(kind, p); a != nil {
			rec.Alerts = append(rec.Alerts, *a)
		}
		if kind == KNormal {
			c.pvtExtras(m, &rec, p)
		}
		if kind == KEmergency {
			m.Reply = c.ack(c.acks.Emergency, p)
		} else {
			m.Reply = c.ack(c.acks.Normal, p)
		}
	}
	if p["vehicle"] != "" && looksLikeReg(p["vehicle"]) {
		rec.Status["vehicle"] = p["vehicle"]
	}
	if len(rec.Status) > 0 || rec.Fix != nil || len(rec.Alerts) > 0 || rec.Trailer != nil {
		m.Records = []track.Record{rec}
	}
	return m, nil
}

// pvtExtras reads the Table 4A(2) fields beyond the common ones: the
// neighbour cells (and, without a GNSS fix, the cells as a network report
// for geolocation), the OTA response and the trailer tag.
func (c *Config) pvtExtras(m *track.Message, rec *track.Record, p map[string]string) {
	if _, ok := p["nmr1Lac"]; ok {
		n, nmr := network(p)
		if len(nmr) > 0 {
			rec.Status["nmr"] = nmr
		}
		if n != nil && (rec.Fix == nil || !rec.Fix.Valid) {
			rec.Network = n
		}
	}
	if r, ok := ParseOTAResponse(p["otaResponse"]); ok && c.otaAnswer(p) {
		t := p["otaResponse"]
		m.Correlation = otaCorrelation(r.Op, itemIDs(r.Items))
		m.Response = &t
		m.Details = r.details()
		for _, it := range r.Items {
			m.Failed = m.Failed || !it.OK
			if it.ID == RFIDTagParam && it.OK && !rec.History {
				tag := it.Value
				rec.Trailer = &tag
			}
		}
		rec.Status["otaLast"] = map[string]any{"source": r.Source, "op": r.Op, "items": len(r.Items)}
		if len(c.otaSources) > 0 && !c.knownSource(r.Source) {
			a := track.NewAlert("ota-unknown-source", r.Source)
			rec.Alerts = append(rec.Alerts, a)
		}
	}
	if p["hasTrailer"] == "1" && rec.Trailer == nil && !rec.History {
		tag := p["trailerId"]
		rec.Trailer = &tag
	}
}

// otaAnswer reports whether a data packet is an answer to an OTA command:
// alert ID 12 or packet type OA (Table 4A(2)), or an alert ID or packet
// type the profile maps to ota-parameter-change. A device that repeats its
// last OTA response in other packets does not answer a new command with
// them.
func (c *Config) otaAnswer(p map[string]string) bool {
	if id, err := strconv.Atoi(p["alertId"]); err == nil && (id == 12 || c.alertIDs[id] == "ota-parameter-change") {
		return true
	}
	t := upper(p["packetType"])
	return t == "OA" || t == "OTA" || c.packetTypes[t] == "ota-parameter-change"
}

func itemIDs(items []OTAItem) []string {
	ids := make([]string, len(items))
	for i, it := range items {
		ids[i] = it.ID
	}
	return ids
}

// otaCorrelation names a Table 4D command, and the OTA response to it, by
// its operation and keys (leading zeros and order aside).
func otaCorrelation(op string, keys []string) string {
	ks := make([]string, len(keys))
	for i, k := range keys {
		ks[i] = strings.TrimLeft(strings.TrimSpace(k), "0")
	}
	sort.Strings(ks)
	return strings.ToUpper(op) + "|" + strings.Join(ks, ",")
}

// Correlation: the answer to a Table 4D command is the OTA response naming
// its operation and keys, and nothing else answers it; a free-text or
// text-form command's answer names none.
func (c *codec) Correlation(content any, _ uint32) (string, bool) {
	if c.cfg.format == "text" {
		return "", false
	}
	content, err := c.cfg.resolveNamed(content, "", "")
	if err != nil {
		return "", false
	}
	cmd, _, err := c.cfg.parseOTA(content)
	if err != nil || cmd == nil {
		return "", false
	}
	return otaCorrelation(cmd.op, cmd.keys), true
}

// knownSource reports whether an OTA response's source is one of
// profile.otaSources (host:port or a number; case and a leading + are
// ignored).
func (c *Config) knownSource(src string) bool {
	norm := func(s string) string { return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(s)), "+") }
	for _, s := range c.otaSources {
		if norm(s) == norm(src) {
			return true
		}
	}
	return false
}

func (c *Config) status(p map[string]string, st map[string]any) {
	for _, k := range []string{"ignition", "mainPower", "emergency"} {
		if b, ok := boolish(p[k]); ok {
			st[k] = b
		}
	}
	for _, k := range []string{"mainVoltage", "batteryVoltage", "pdop", "hdop", "analogInput1", "analogInput2", "deltaDistance",
		"accelX", "accelY", "accelZ", "tiltX", "tiltY"} {
		if v, ok := num(p[k]); ok {
			st[k] = v
		}
	}
	if v, ok := num(p["odometerKm"]); ok {
		st["odometer"] = math.Round(v * 1000)
	}
	if v, ok := num(p["gsm"]); ok {
		st["gsm"] = int(v)
	}
	switch upper(p["tamper"]) {
	case "C":
		st["boxOpen"] = false
	case "O":
		st["boxOpen"] = true
	}
	for _, k := range []string{"operator", "mcc", "mnc", "lac", "cellId", "digitalInputs", "digitalOutputs", "frame"} {
		if v := p[k]; v != "" {
			st[k] = v
		}
	}
	// Emergency packets: the positioning provider (G fine GNSS, N coarse
	// or network) and the number the control centre answers to.
	if v := upper(p["provider"]); v == "G" || v == "N" {
		st["provider"] = v
	}
	if v := p["replyNumber"]; v != "" && v != "0" {
		st["replyNumber"] = v
	}
	if p["sms"] == "1" {
		st["emergencyBy"] = "sms"
	}
}

func (c *Config) alert(kind string, p map[string]string) *track.Alert {
	t := upper(p["packetType"])
	if kind == KEmergency {
		if t == "SEM" {
			a := track.NewAlert("emergency-off", "SEM")
			return &a
		}
		a := track.NewAlert("emergency", "EMR")
		return &a
	}
	// Alert IDs are two digits since Amendment 3 (item 19: 01 to 09).
	id, _ := strconv.Atoi(p["alertId"])
	if typ, ok := c.alertIDs[id]; ok && id > 2 {
		a := track.NewAlert(typ, fmt.Sprintf("%s/%d", t, id))
		return &a
	}
	if typ, ok := c.packetTypes[t]; ok {
		a := track.NewAlert(typ, t)
		if p["alertId"] != "" {
			a.Code = t + "/" + p["alertId"]
		}
		return &a
	}
	return nil
}

func (c *Config) ack(tmpl string, p map[string]string) []byte {
	if tmpl == "" {
		return nil
	}
	return []byte(strings.NewReplacer("{imei}", p["imei"], "{frame}", p["frame"]).Replace(tmpl))
}

// ---- commands ---------------------------------------------------------------

// Command is an OTA command in the older text form (commandFormat text).
type Command struct {
	Op    string `json:"op,omitempty"`
	Param string `json:"param,omitempty"`
	Value string `json:"value,omitempty"`
	Text  string `json:"text,omitempty"`
}

// OTAText is the command line of an OTA command in the older text form:
// {"op": "SET", "param": "SL", "value": "60"} is "SET SL:60".
func OTAText(content any) (string, error) {
	var cmd Command
	switch v := content.(type) {
	case string:
		cmd.Text = v
	default:
		b, _ := json.Marshal(v)
		if err := track.StrictJSON(b, &cmd); err != nil {
			return "", fmt.Errorf(`an AIS-140 command is {"op": "SET"|"GET"|"CLR", "param": …, "value": …} or {"text": …}: %w`, err)
		}
	}
	if cmd.Text != "" {
		if strings.ContainsAny(cmd.Text, "\r\n") {
			return "", errors.New("a command is one line")
		}
		return cmd.Text, nil
	}
	param := strings.ToUpper(cmd.Param)
	if param == "" || strings.ContainsAny(param, " :,\r\n*$") || strings.ContainsAny(cmd.Value, "\r\n*$") {
		return "", errors.New("the command needs a parameter name without spaces, ':' or ',' and a one-line value")
	}
	switch strings.ToUpper(cmd.Op) {
	case "SET":
		if cmd.Value == "" {
			return "", errors.New("SET needs a value")
		}
		return "SET " + param + ":" + cmd.Value, nil
	case "GET":
		return "GET " + param, nil
	case "CLR":
		return "CLR " + param, nil
	}
	return "", fmt.Errorf("op %q is not SET, GET or CLR", cmd.Op)
}

// Command frames a command with the profile's otaPassword, if any.
func (c *codec) Command(imei string, content any, seq uint32) ([]byte, bool, error) {
	return c.CommandWithPassword(imei, "", content, seq)
}

// CommandWithPassword frames a command for the device: Table 4D with the
// device's password (password, else profile.otaPassword), or the older
// text form. Options.CheckCommand, when set, sees the frame first.
func (c *codec) CommandWithPassword(imei, password string, content any, seq uint32) ([]byte, bool, error) {
	out, answers, err := c.deviceCommand(imei, password, content, seq)
	if err != nil {
		return nil, false, err
	}
	if c.check != nil {
		if err := c.check(out); err != nil {
			return nil, false, fmt.Errorf("OTA command refused: %w", err)
		}
	}
	return out, answers, nil
}

func (c *codec) deviceCommand(imei, pw string, content any, _ uint32) ([]byte, bool, error) {
	if pw == "" {
		pw = c.cfg.otaPassword
	}
	content, err := c.cfg.resolveNamed(content, imei, pw)
	if err != nil {
		return nil, false, err
	}
	if c.cfg.format == "text" {
		text, err := OTAText(content)
		if err != nil {
			return nil, false, err
		}
		out := strings.NewReplacer("{cmd}", text, "{imei}", imei).Replace(c.cfg.cmdTemplate)
		return []byte(out), c.cfg.answers, nil
	}
	cmd, text, err := c.cfg.parseOTA(content)
	if err != nil {
		return nil, false, err
	}
	if cmd == nil {
		return []byte(text + "\r\n"), c.cfg.answers, nil
	}
	if pw == "" {
		return nil, false, fmt.Errorf("no command password for %s: set the device's commandPassword (or profile.otaPassword); a free-text command ({\"text\": …}) goes out without one", imei)
	}
	if strings.ContainsAny(pw, ",*$\r\n") {
		return nil, false, errors.New("the command password must not contain ',', '*', '$' or a line break")
	}
	return []byte(cmd.frame(imei, pw, c.sumDollar)), c.cfg.answers, nil
}

// SMSRequest names the SMS requests of AIS-140 (Amendment 2, 8.4):
// {"op": "HCHK"} a health check, {"op": "ACTV"} an activation.
func (c *codec) SMSRequest(content any) (string, bool) {
	m, ok := content.(map[string]any)
	if !ok || len(m) != 1 {
		return "", false
	}
	op, _ := m["op"].(string)
	switch strings.ToUpper(op) {
	case "HCHK":
		return "HCHK", true
	case "ACTV":
		return "ACTV", true
	}
	return "", false
}
