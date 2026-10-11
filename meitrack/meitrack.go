// Package meitrack is the Meitrack GPRS tracker protocol of the T1, T3,
// T333, T366, MVT100/340/380/600/800, TC68S, P88L and the other Meitrack
// trackers that report in this text protocol: frame reading and writing,
// decoding into track.Message, report confirmation and command framing.
// Our own implementation from Meitrack's public protocol documents:
//
//   - MEITRACK GPRS Protocol V1.8 (2016-12-19), all models:
//     https://www.meitrack.com/cd-download/Protocols/MEITRACK_GPRS_Protocol.pdf
//   - MEITRACK T1 & T333 GPRS Protocol V1.4 (2018-12-04):
//     https://www.meitrack.com/cd-download/Protocols/MEITRACK_T1_T333_GPRS_Protocol.pdf
//   - MEITRACK T366 & T366G & T366L GPRS Protocol V1.5 (2019-07-02):
//     https://www.meitrack.com/cd-download/Protocols/MEITRACK_T366_T366G_T366L_GPRS_Protocol.pdf
//   - MEITRACK GPRS (CCE ID) Protocol V1.0 (2025-03-30), the binary batch:
//     https://www.meitrack.com/wp-content/uploads/h2025/MEITRACK_GPRS(CCE_ID)_Total_protocol_V1.0--20250330.pdf
//
// Framing (both directions; ReadFrame, Encode): a header ("$$" from the
// device, "@@" from the server), one data identifier character, the
// decimal length of everything from the first comma to the closing CR LF,
// then ",<IMEI>,<command type>,<data>*<checksum>\r\n". The checksum
// (Checksum) is the low byte of the sum of every byte from the header to
// the '*', as two upper-case hexadecimal digits. There is no login frame:
// every frame names the IMEI, and the first one of a connection identifies
// the tracker.
//
// Device frames handled:
//
//   - AAA, the event report: event code, position (degrees, km/h, degrees
//     from north, UTC unless profile.timezone), satellites, GSM level, HDOP,
//     altitude, mileage and run time, the serving cell, the eight inputs and
//     outputs, the analog inputs, the assisted event data (geofence number,
//     RFID), protocol version, fuel and temperature sensors. Event codes
//     become alerts (events, below); input events on the ignition input
//     (ignitionInput) become ignition-on/off.
//   - CCE, the binary batch of newer firmware (T633L, T399L, T711L, MD
//     series): each data packet becomes a record; a batch of more than one
//     packet, or one sent while the device still holds cached records, is
//     history.
//   - CCC, an older binary batch with no public description: passed over
//     with the warning meitrack.unknownMessage (configure the device for
//     AAA reports).
//   - Command answers: any other command type ("C01,OK", "A12,OK", the
//     E91 version answer); the AAA report with event 34 is the answer to
//     A10. Unknown command types are taken as answers, so a command the
//     codec does not know still completes.
//
// The device expects no acknowledgement of its reports in its default
// event transmission mode (C03,0). With C03,1, used over UDP, every report
// must be confirmed with AFF; profile.confirmEvents sends that AFF,1.
//
// Commands: {"text": "C01,0,12222"} is the command type and its
// parameters as the protocol documents write them; the codec adds the
// header, a data identifier (Identifier), the IMEI, the length and the
// checksum. The tracker answers with the same data identifier and command
// type, and the codec is a track.Correlator, so an answer completes only
// its own command (a late answer to a timed-out command does not complete
// the next one). Named commands (track.Named):
//
//	engineStop     C01,<stopSpeed>,<outputs>   the relay output (relayOutput, default 1) on, the others unchanged: C01,0,12222
//	engineResume   C01,0,<outputs>             the relay output off: C01,0,02222
//	locate         A10                         answered by an AAA report with event 34
//	interval       A12,<seconds/10>            time-interval tracking, in tens of seconds (10 to 655350 s)
//
// reboot is not offered: the documents describe no full device restart,
// only module restarts (F00,1,1 restarts the GSM and GPS modules on T1,
// T333 and T366; F01 the GSM module, F02 the GPS module, on every model).
// Set profile.namedCommands.reboot to one of them to offer it.
//
// The profile (NewCodec; Profile):
//
//	checkCrc: true                 # default true; false accepts frames whose checksum does not match
//	timezone: UTC                  # zone of the device's GPRS clock (default UTC, the device's default B36,0)
//	ignitionInput: 3               # input wired to ignition (default 3: T1, T3, T333, MVT600; 4 for MVT380/MVT800, 2 for MVT100/MVT340; 0 none)
//	analog: raw                    # default raw (AD values only); div100 (T311, T322X, T333, T355, T366), t1 (T1, T3, MVT100, MVT600, MVT800, TC68S) or mvt380 (MVT340, MVT380)
//	analogHex: true                # default true: AAA analog values are hexadecimal, as the field table says; false reads them as decimal (as the documents' examples read)
//	events: {"44": gsm-jamming}    # extra or changed event codes → alert type; "" drops an event's alert
//	relayOutput: 1                 # output (1 to 5) that drives the immobiliser relay (default 1)
//	relayInverted: false           # default false; true when the relay stops the engine with the output off
//	stopSpeed: 0                   # C01 speed limit in km/h (default 0: at once; the device then waits until slower)
//	confirmEvents: false           # default false; true answers every report with AFF,1 (C03,1 mode, UDP)
//	matchIdentifier: true          # default true; false lets an answer with another data identifier complete a command of its type
//	namedCommands: {}              # replace a named command's text ({seconds} is in seconds), e.g. {reboot: "F00,1,1"}
//	failureWords: [fail, error, invalid]   # default; an answer holding one fails the command
package meitrack

import (
	"bufio"
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

// name is the protocol's name in errors.
const name = "meitrack"

// Interval bounds the A12 interval: 1 to 65535 tens of seconds.
var Interval = track.IntervalRange{Min: 10, Max: 655350, Step: 10}

// NamedActions are the named commands the protocol has: all but reboot,
// which a profile's namedCommands may add.
var NamedActions = []string{track.ActionEngineStop, track.ActionEngineResume, track.ActionLocate, track.ActionInterval}

// Profile is the manufacturer-variation settings.
type Profile struct {
	// CheckCRC (default true) drops frames whose checksum does not match;
	// false accepts them.
	CheckCRC *bool `json:"checkCrc,omitempty"`
	// Timezone is the zone of the device's GPRS clock (default UTC, the
	// device's default; command B36 changes it on the device).
	Timezone string `json:"timezone,omitempty"`
	// IgnitionInput is the input wired to the ignition (default 3, as on
	// T1, T3, T333 and MVT600; 4 on MVT380 and MVT800, 2 on MVT100 and
	// MVT340; 0 when none is).
	IgnitionInput *int `json:"ignitionInput,omitempty"`
	// Analog is how the analog inputs convert to volts: raw (default, the
	// AD values only), div100, t1 or mvt380, as the model's protocol
	// document gives them.
	Analog string `json:"analog,omitempty"`
	// AnalogHex (default true) reads an AAA report's analog values as
	// hexadecimal, as the protocol's field table says; false reads them as
	// decimal, which is how the documents' examples give plausible
	// voltages.
	AnalogHex *bool `json:"analogHex,omitempty"`
	// Events maps more or other event codes to alert types; "" drops an
	// event's alert.
	Events map[string]string `json:"events,omitempty"`
	// RelayOutput is the output (1 to 5) that drives the immobiliser relay
	// (default 1).
	RelayOutput int `json:"relayOutput,omitempty"`
	// RelayInverted (default false) is for relays that stop the engine with
	// the output off.
	RelayInverted bool `json:"relayInverted,omitempty"`
	// StopSpeed is the speed limit of C01 in km/h (default 0: the output
	// changes at once; 1 to 255: the device waits until it is slower).
	StopSpeed int `json:"stopSpeed,omitempty"`
	// ConfirmEvents (default false) answers every report with AFF,1, for
	// devices set to wait for confirmation (C03,1, usual over UDP).
	ConfirmEvents bool `json:"confirmEvents,omitempty"`
	// MatchIdentifier (default true) completes a command only with an
	// answer carrying its data identifier; false accepts any answer of the
	// command's type.
	MatchIdentifier *bool `json:"matchIdentifier,omitempty"`
	// NamedCommands replaces the text of named commands for firmware that
	// differs ({seconds} is the interval in seconds, {imei} the IMEI).
	NamedCommands track.NamedTemplates `json:"namedCommands,omitempty"`
	// FailureWords are the words (any case) that fail a command when its
	// answer holds one (default fail, error, invalid).
	FailureWords []string `json:"failureWords,omitempty"`
}

type config struct {
	crc      bool
	loc      *time.Location
	ign      int
	analog   string
	adBase   int
	events   map[int]track.Alert
	relay    int
	inverted bool
	speed    int
	confirm  bool
	matchID  bool
	named    track.NamedTemplates
	fail     []string
}

// NewCodec validates a profile (empty for the defaults) and returns a
// factory of codecs, one per connection. Each codec is a track.Correlator.
func NewCodec(raw json.RawMessage) (func() track.Codec, error) {
	var p Profile
	if err := track.StrictJSON(raw, &p); err != nil {
		return nil, err
	}
	c := config{crc: p.CheckCRC == nil || *p.CheckCRC, loc: time.UTC, ign: 3, analog: "raw", adBase: 16, relay: 1,
		inverted: p.RelayInverted, speed: p.StopSpeed, confirm: p.ConfirmEvents,
		matchID: p.MatchIdentifier == nil || *p.MatchIdentifier, named: p.NamedCommands, events: map[int]track.Alert{}}
	if p.AnalogHex != nil && !*p.AnalogHex {
		c.adBase = 10
	}
	if p.Timezone != "" {
		l, err := time.LoadLocation(p.Timezone)
		if err != nil {
			return nil, fmt.Errorf("timezone %q: %w", p.Timezone, err)
		}
		c.loc = l
	}
	if p.IgnitionInput != nil {
		if *p.IgnitionInput < 0 || *p.IgnitionInput > 8 {
			return nil, errors.New("ignitionInput is 0 (none) or an input from 1 to 8")
		}
		c.ign = *p.IgnitionInput
	}
	if p.Analog != "" {
		if _, ok := analogScales[p.Analog]; !ok && p.Analog != "raw" {
			return nil, fmt.Errorf("analog %q is raw, div100, t1 or mvt380", p.Analog)
		}
		c.analog = p.Analog
	}
	if p.RelayOutput != 0 {
		if p.RelayOutput < 1 || p.RelayOutput > 5 {
			return nil, errors.New("relayOutput is an output from 1 to 5")
		}
		c.relay = p.RelayOutput
	}
	if p.StopSpeed < 0 || p.StopSpeed > 255 {
		return nil, errors.New("stopSpeed is 0 (at once) or a speed from 1 to 255 km/h")
	}
	if err := p.NamedCommands.Check(false); err != nil {
		return nil, err
	}
	fw, err := track.FailureWords(p.FailureWords, "fail", "error", "invalid")
	if err != nil {
		return nil, err
	}
	c.fail = fw
	for k, v := range defaultEvents {
		c.events[k] = v
	}
	for k, v := range p.Events {
		n, err := strconv.Atoi(k)
		if err != nil || n < 0 || n > 65535 {
			return nil, fmt.Errorf("events: %q must be an event code such as \"44\"", k)
		}
		if v == "" {
			delete(c.events, n)
			continue
		}
		c.events[n] = track.NewAlert(v, k)
	}
	return func() track.Codec { return &codec{cfg: c} }, nil
}

func major(typ, code string) track.Alert {
	return track.Alert{Type: typ, Severity: track.Major, Code: code}
}

// defaultEvents are the event codes that are alerts (the common table of
// the GPRS Protocol V1.8 section 1.3 and the T366 V1.5 additions). Input
// events (1 to 5, 9 to 13) are status; event 1 is the SOS input on the
// vehicle trackers. Periodic reports (31 to 35) and the rest are status.
var defaultEvents = map[int]track.Alert{
	1:   track.NewAlert("emergency", "1"),
	17:  track.NewAlert("low-battery", "17"),
	18:  track.NewAlert("main-power-low", "18"),
	19:  track.NewAlert("over-speed", "19"),
	20:  track.NewAlert("geofence-enter", "20"),
	21:  track.NewAlert("geofence-exit", "21"),
	22:  track.NewAlert("main-power-restored", "22"),
	23:  track.NewAlert("main-power-removed", "23"),
	28:  major("gnss-antenna-cut", "28"),
	36:  track.NewAlert("towing", "36"),
	44:  major("gsm-jamming", "44"),
	50:  track.NewAlert("temperature-high", "50"),
	51:  track.NewAlert("temperature-low", "51"),
	53:  track.NewAlert("low-fuel", "53"),
	54:  major("fuel-theft", "54"),
	58:  major("vehicle-theft", "58"),
	78:  track.NewAlert("impact", "78"),
	90:  track.NewAlert("rash-turning", "90"),
	91:  track.NewAlert("rash-turning", "91"),
	129: track.NewAlert("harsh-braking", "129"),
	130: track.NewAlert("harsh-acceleration", "130"),
	135: track.NewAlert("fatigue-driving", "135"),
}

// analogScales convert the AD values to volts: AD1-3, battery (AD4) and
// external power (AD5) multipliers, per the protocol documents' formulas.
var analogScales = map[string][3]float64{
	"div100": {1.0 / 100, 1.0 / 100, 1.0 / 100},
	"t1":     {3.3 * 2 / 4096, 3.3 * 2 / 4096, 3.3 * 16 / 4096},
	"mvt380": {6.0 / 1024, 3.0 * 2 / 1024, 3.0 * 16 / 1024},
}

type codec struct {
	cfg  config
	imei string
}

// ---- framing ----------------------------------------------------------------

const (
	maxFrame = 65535
	// MaxCommand is the longest command text (command type and
	// parameters) a codec frames.
	MaxCommand = 200
)

// Frame is one frame, either direction.
type Frame struct {
	Server bool   // "@@" (server to device) rather than "$$"
	ID     byte   // data identifier
	IMEI   string // the second field
	Type   string // the command type: AAA, CCE, C01, …
	Data   []byte // what follows the type's comma, up to '*' ("" when none)
	Raw    []byte // the frame as received
	// CRCOK reports whether the checksum matched.
	CRCOK bool
}

// Checksum is the protocol's checksum of b: the low byte of the sum of its
// bytes.
func Checksum(b []byte) byte {
	var s byte
	for _, v := range b {
		s += v
	}
	return s
}

// Encode builds a frame: header "@@" (server) or "$$" (device), the data
// identifier, the length, the IMEI, and body (the command type and its
// data, written as "C01,0,12222"), with the checksum and CR LF.
func Encode(server bool, id byte, imei string, body []byte) []byte {
	tail := len(imei) + len(body) + 2 + 5 // ",imei," + body + "*XX\r\n"
	h := "$$"
	if server {
		h = "@@"
	}
	b := make([]byte, 0, tail+10)
	b = append(b, h...)
	b = append(b, id)
	b = strconv.AppendInt(b, int64(tail), 10)
	b = append(b, ',')
	b = append(b, imei...)
	b = append(b, ',')
	b = append(b, body...)
	b = append(b, '*')
	b = append(b, fmt.Sprintf("%02X", Checksum(b))...)
	return append(b, '\r', '\n')
}

// ErrLength is a frame whose length or ending does not hold together.
var ErrLength = errors.New("meitrack: frame length does not match")

// ReadFrame reads the next frame, skipping bytes until a header. A frame
// whose length does not hold together returns ErrLength (the stream reads
// on from the next header).
func ReadFrame(r *bufio.Reader) (*Frame, error) {
	for {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		if b != '$' && b != '@' {
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
		id, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		head := []byte{b, b, id}
		n := 0
		for {
			c, err := r.ReadByte()
			if err != nil {
				return nil, err
			}
			if c == ',' {
				_ = r.UnreadByte()
				break
			}
			if c < '0' || c > '9' || len(head) > 8 {
				return nil, ErrLength
			}
			head = append(head, c)
			n = n*10 + int(c-'0')
		}
		if n < 8 || n > maxFrame {
			return nil, ErrLength
		}
		rest := make([]byte, n)
		if _, err := io.ReadFull(r, rest); err != nil {
			return nil, err
		}
		if rest[n-2] != '\r' || rest[n-1] != '\n' || rest[n-5] != '*' {
			return nil, ErrLength
		}
		raw := append(head, rest...)
		f := &Frame{Server: b == '@', ID: id, Raw: raw}
		sum, err := strconv.ParseUint(string(rest[n-4:n-2]), 16, 8)
		f.CRCOK = err == nil && byte(sum) == Checksum(raw[:len(raw)-4])
		body := rest[1 : n-5]
		i := indexByte(body, ',')
		if i < 0 {
			f.IMEI = string(body)
			return f, nil
		}
		f.IMEI = string(body[:i])
		body = body[i+1:]
		// The binary batches carry their data straight after "CCE,".
		if j := indexByte(body, ','); j >= 0 {
			f.Type, f.Data = string(body[:j]), body[j+1:]
		} else {
			f.Type = string(body)
		}
		return f, nil
	}
}

func indexByte(b []byte, c byte) int {
	for i, v := range b {
		if v == c {
			return i
		}
	}
	return -1
}

// ---- decoding ---------------------------------------------------------------

func (c *codec) Decode(r *bufio.Reader) (*track.Message, error) {
	f, err := ReadFrame(r)
	if errors.Is(err, ErrLength) {
		return nil, &track.Skip{Warning: track.Warning{Code: "shortPacket",
			Msg: "A packet whose length field does not match its content was passed over (the connection stays up)."}}
	}
	if err != nil {
		return nil, err
	}
	if !f.CRCOK && c.cfg.crc {
		return nil, &track.Skip{Warning: track.Warning{Code: "crcMismatch", Setting: "profile.checkCrc", Detail: clip(string(f.Raw)),
			Msg: "A packet whose checksum does not match was dropped. Set profile.checkCrc to false if the device computes it another way."}}
	}
	if f.Server {
		return nil, &track.Skip{Warning: track.Warning{Code: "unknownPacket", Detail: clip(string(f.Raw)),
			Msg: "A packet in the server's direction (@@) came from the tracker and was passed over."}}
	}
	m, err := c.message(f)
	if err != nil {
		return nil, err
	}
	m.Raw = f.Raw
	return m, nil
}

func clip(s string) string {
	if len(s) > 64 {
		return s[:64]
	}
	return s
}

func (c *codec) message(f *Frame) (*track.Message, error) {
	m := &track.Message{IMEI: f.IMEI}
	if c.imei == "" {
		c.imei, m.Login = f.IMEI, true
	}
	confirm := func() {
		if c.cfg.confirm {
			m.Reply = Encode(true, f.ID, f.IMEI, []byte("AFF,1"))
		}
	}
	switch f.Type {
	case "AAA":
		rec, ev, warn := c.aaa(string(f.Data))
		m.Records, m.Kind = []track.Record{rec}, "normal"
		if warn != nil {
			m.Warnings = append(m.Warnings, *warn)
		}
		if ev == 34 { // the answer to A10
			text := "AAA," + string(f.Data)
			m.Response, m.Kind, m.Correlation = &text, "response", c.correlation(f.ID, "A10")
		} else if ev == 1 {
			m.Kind = "emergency"
		}
		confirm()
	case "CCE":
		recs, warns, err := c.cce(f.Data)
		if err != nil {
			return nil, &track.Skip{Warning: track.Warning{Code: "shortPacket", Detail: err.Error(),
				Msg: "A CCE report that ends before its records do was passed over (the connection stays up)."}}
		}
		m.Records, m.Warnings, m.Kind = recs, warns, "normal"
		confirm()
	case "CCC":
		return nil, &track.Skip{Warning: track.Warning{Code: "unknownMessage", Detail: "CCC",
			Msg: "A CCC report (an older binary batch with no public description) was passed over. Set the device to send AAA reports (Meitrack Manager, GPRS settings)."}}
	case "AFF":
		// The answer to a confirmation (confirmEvents): nothing to keep.
		m.Kind = "ack"
	case "D00":
		return nil, &track.Skip{Warning: track.Warning{Code: "unknownMessage", Detail: "D00",
			Msg: "A picture packet (D00) was passed over; this codec does not store camera pictures."}}
	default:
		typ, text := f.Type, f.Type
		if len(f.Data) > 0 {
			text += "," + string(f.Data)
		}
		if !commandType(typ) {
			// E91 answers "FWV1.00,12345678" with no command type.
			typ = "E91"
		}
		m.Response, m.Kind = &text, "response"
		m.Failed = track.AnswerFailed(text, c.cfg.fail)
		m.Correlation = c.correlation(f.ID, typ)
		if typ == "E91" && !commandType(f.Type) {
			m.Details = map[string]any{"firmware": f.Type}
			if len(f.Data) > 0 {
				m.Details["serial"] = string(f.Data)
			}
		}
	}
	return m, nil
}

// commandType reports whether s looks like a command type: a letter and
// two letters or digits.
func commandType(s string) bool {
	if len(s) != 3 || !(s[0] >= 'A' && s[0] <= 'Z') {
		return false
	}
	for i := 1; i < 3; i++ {
		ch := s[i]
		if !(ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9') {
			return false
		}
	}
	return true
}

func (c *codec) correlation(id byte, typ string) string {
	if !c.cfg.matchID {
		return typ
	}
	return string(id) + ":" + typ
}

// aaa decodes an AAA report's fields (after "AAA,"); it returns the record,
// the event code (-1 when unreadable) and a warning for a field it could
// not read.
func (c *codec) aaa(s string) (track.Record, int, *track.Warning) {
	f := strings.Split(s, ",")
	get := func(i int) string {
		if i < len(f) {
			return strings.TrimSpace(f[i])
		}
		return ""
	}
	rec := track.Record{Status: map[string]any{}}
	ev, err := strconv.Atoi(get(0))
	if err != nil {
		ev = -1
	} else {
		rec.Status["event"] = ev
	}
	var warn *track.Warning
	lat, e1 := strconv.ParseFloat(get(1), 64)
	lon, e2 := strconv.ParseFloat(get(2), 64)
	t, e3 := time.ParseInLocation("060102150405", get(3), c.cfg.loc)
	if e1 == nil && e2 == nil && e3 == nil && math.Abs(lat) <= 90 && math.Abs(lon) <= 180 {
		x := &track.Fix{Time: t.UTC(), Lat: lat, Lon: lon, Valid: get(4) == "A"}
		if v, err := strconv.Atoi(get(5)); err == nil {
			x.Sats = track.I(v)
		}
		if v, err := strconv.ParseFloat(get(7), 64); err == nil {
			x.Speed = track.F(v)
		}
		if v, err := strconv.ParseFloat(get(8), 64); err == nil {
			x.Heading = track.F(v)
		}
		if v, err := strconv.ParseFloat(get(9), 64); err == nil {
			x.HDOP = track.F(v)
		}
		if v, err := strconv.ParseFloat(get(10), 64); err == nil {
			x.Alt = track.F(v)
		}
		rec.Fix, rec.Time = x, x.Time
	} else if get(1) != "" || get(3) != "" {
		warn = &track.Warning{Code: "fieldUnreadable", Detail: clip(s),
			Msg: "An AAA report's position or time could not be read; its other values were kept."}
	}
	if v, err := strconv.Atoi(get(6)); err == nil {
		rec.Status["gsm"] = v
	}
	if v, err := strconv.ParseUint(get(11), 10, 32); err == nil {
		rec.Status["odometer"] = int64(v)
	}
	if v, err := strconv.ParseUint(get(12), 10, 32); err == nil {
		rec.Status["runTime"] = int64(v)
	}
	if bs := strings.Split(get(13), "|"); len(bs) == 4 {
		mcc, _ := strconv.Atoi(bs[0])
		mnc, _ := strconv.Atoi(bs[1])
		lac, e1 := strconv.ParseUint(bs[2], 16, 32)
		cid, e2 := strconv.ParseUint(bs[3], 16, 32)
		if mcc > 0 && e1 == nil && e2 == nil {
			rec.Network = &track.Network{Cells: []track.Cell{{MCC: mcc, MNC: mnc, LAC: int(lac), CID: int64(cid)}}}
		}
	}
	var in, out uint32
	hasIO := false
	if v, err := strconv.ParseUint(get(14), 16, 16); err == nil {
		out, in, hasIO = uint32(v&0xFF), uint32(v>>8), true
	}
	var ad []float64
	for i, a := range strings.Split(get(15), "|") {
		if v, err := strconv.ParseUint(a, c.cfg.adBase, 32); err == nil && a != "" {
			ad = append(ad, float64(v))
		} else if a != "" || i > 0 {
			ad = append(ad, math.NaN())
		}
	}
	c.analogStatus(rec.Status, ad, false)
	extra := get(16)
	switch ev {
	case 20, 21:
		if n, ok := leU32Hex(extra); ok {
			rec.Status["geofence"] = n
		}
	case 37:
		if extra != "" {
			rec.Status["rfid"] = extra
		}
	}
	if v := get(19); len(v) == 4 {
		if n, err := strconv.ParseUint(v, 16, 16); err == nil {
			rec.Status["fuel"] = float64(n>>8) + float64(n&0xFF)/100
		}
	}
	if v := get(20); v != "" {
		temps := map[string]any{}
		for _, t := range strings.Split(v, "|") {
			if len(t) != 6 {
				continue
			}
			no, e1 := strconv.ParseUint(t[:2], 16, 8)
			ip, e2 := strconv.ParseUint(t[2:4], 16, 8)
			dp, e3 := strconv.ParseUint(t[4:], 16, 8)
			if e1 != nil || e2 != nil || e3 != nil {
				continue
			}
			// The integer part is a signed byte (-127 to 127 °C).
			deg := float64(int8(ip))
			frac := float64(dp) / 100
			if deg < 0 {
				deg -= frac
			} else {
				deg += frac
			}
			temps[strconv.Itoa(int(no))] = math.Round(deg*100) / 100
		}
		if len(temps) > 0 {
			rec.Status["temperatures"] = temps
		}
	}
	if hasIO {
		c.ioStatus(rec.Status, in, out, 8)
	}
	rec.Alerts = c.alerts(ev, rec.Status)
	return rec, ev, warn
}

// leU32Hex reads "02 00 00 00"-style little-endian assisted event data as
// written in AAA reports (eight hexadecimal digits, spaces allowed).
func leU32Hex(s string) (int, bool) {
	s = strings.ReplaceAll(s, " ", "")
	if len(s) != 8 {
		return 0, false
	}
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return 0, false
	}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(v))
	return int(binary.LittleEndian.Uint32(b[:])), true
}

// ioStatus writes din1…n and dout1…n, and ignition from the ignition input.
func (c *codec) ioStatus(st map[string]any, in, out uint32, n int) {
	for i := 0; i < n; i++ {
		st["din"+strconv.Itoa(i+1)] = in&(1<<i) != 0
		if out != math.MaxUint32 {
			st["dout"+strconv.Itoa(i+1)] = out&(1<<i) != 0
		}
	}
	if c.cfg.ign > 0 {
		st["ignition"] = in&(1<<(c.cfg.ign-1)) != 0
	}
}

// analogStatus writes the analog inputs: adc1…5 as reported and, with a
// model's formula, ad1…3, batteryVoltage and externalVoltage in volts.
// volts says the values are already hundredths of a volt (CCE).
func (c *codec) analogStatus(st map[string]any, ad []float64, volts bool) {
	sc, scaled := analogScales[c.cfg.analog]
	if volts {
		sc, scaled = analogScales["div100"], true
	}
	for i, v := range ad {
		if math.IsNaN(v) {
			continue
		}
		if !volts {
			st["adc"+strconv.Itoa(i+1)] = v
		}
		if !scaled {
			continue
		}
		var k string
		var mul float64
		switch i {
		case 0, 1, 2:
			k, mul = "ad"+strconv.Itoa(i+1), sc[0]
		case 3:
			k, mul = "batteryVoltage", sc[1]
		case 4:
			k, mul = "externalVoltage", sc[2]
		default:
			continue
		}
		st[k] = math.Round(v*mul*100) / 100
	}
}

// alerts maps an event code to alerts; input events on the ignition input
// are ignition-on/off.
func (c *codec) alerts(ev int, st map[string]any) []track.Alert {
	if ev < 0 {
		return nil
	}
	code := strconv.Itoa(ev)
	if a, ok := c.cfg.events[ev]; ok {
		return []track.Alert{a}
	}
	if ign := c.cfg.ign; ign > 0 {
		switch ev {
		case ign:
			st["ignition"] = true
			return []track.Alert{track.NewAlert("ignition-on", code)}
		case ign + 8:
			st["ignition"] = false
			return []track.Alert{track.NewAlert("ignition-off", code)}
		}
	}
	return nil
}

// ---- CCE --------------------------------------------------------------------

// epoch2000 is the start of CCE times.
var epoch2000 = time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)

type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil || n > len(r.b) || n < 0 {
		r.err = io.ErrUnexpectedEOF
		return make([]byte, max(n, 0))
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}
func (r *reader) u8() int     { return int(r.take(1)[0]) }
func (r *reader) u16() int    { return int(binary.LittleEndian.Uint16(r.take(2))) }
func (r *reader) u32() uint32 { return binary.LittleEndian.Uint32(r.take(4)) }

// id reads a parameter ID: one byte, or two when the first is 0xF8 or
// 0xFE (the documents' extended IDs such as 0xFE90 and 0xF826).
func (r *reader) id() int {
	v := r.u8()
	if v == 0xF8 || v == 0xFE {
		v = v<<8 | r.u8()
	}
	return v
}

// cce decodes a CCE batch's binary data (after "CCE,").
func (c *codec) cce(b []byte) ([]track.Record, []track.Warning, error) {
	r := &reader{b: b}
	remaining := r.u32()
	n := r.u16()
	if r.err != nil {
		return nil, nil, r.err
	}
	history := n > 1 || remaining > 0
	var out []track.Record
	var warns []track.Warning
	for i := 0; i < n; i++ {
		l := r.u16()
		pkt := r.take(l)
		if r.err != nil {
			return nil, nil, fmt.Errorf("CCE packet %d of %d: %w", i+1, n, r.err)
		}
		rec, err := c.ccePacket(pkt)
		if err != nil {
			warns = append(warns, track.Warning{Code: "fieldUnreadable", Detail: fmt.Sprintf("CCE packet %d: %v", i+1, err),
				Msg: "A CCE data packet whose parameters do not fill its length was passed over; the batch's other packets were kept."})
			continue
		}
		rec.History = history
		out = append(out, rec)
	}
	return out, warns, nil
}

func (c *codec) ccePacket(b []byte) (track.Record, error) {
	r := &reader{b: b}
	_ = r.u16() // number of IDs
	one, two, four := map[int]int{}, map[int]int{}, map[int]uint32{}
	vars := map[int][]byte{}
	for range r.u8() {
		one[r.id()] = r.u8()
	}
	for range r.u8() {
		two[r.id()] = r.u16()
	}
	for range r.u8() {
		four[r.id()] = r.u32()
	}
	if len(r.b) > 0 {
		for range r.u8() {
			id := r.id()
			vars[id] = r.take(r.u8())
		}
	}
	if r.err != nil {
		return track.Record{}, r.err
	}
	if len(r.b) != 0 {
		return track.Record{}, fmt.Errorf("%d bytes left over", len(r.b))
	}
	rec := track.Record{Status: map[string]any{}}
	ev := -1
	if v, ok := two[0x40]; ok {
		ev = v
	} else if v, ok := one[0x01]; ok {
		ev = v
	}
	if ev >= 0 {
		rec.Status["event"] = ev
	}
	lat, okLat := four[0x02]
	lon, okLon := four[0x03]
	ts, okT := four[0x04]
	if okLat && okLon && okT {
		x := &track.Fix{Time: epoch2000.Add(time.Duration(ts) * time.Second), Lat: float64(int32(lat)) / 1e6,
			Lon: float64(int32(lon)) / 1e6, Valid: one[0x05] == 1}
		if v, ok := one[0x06]; ok {
			x.Sats = track.I(v)
		}
		if v, ok := two[0x08]; ok {
			x.Speed = track.F(float64(v))
		}
		if v, ok := two[0x09]; ok {
			x.Heading = track.F(float64(v))
		}
		if v, ok := two[0x0A]; ok {
			x.HDOP = track.F(float64(v) / 10)
		}
		if v, ok := two[0x0B]; ok {
			x.Alt = track.F(float64(int16(v)))
		}
		rec.Fix, rec.Time = x, x.Time
	}
	if v, ok := one[0x07]; ok {
		rec.Status["gsm"] = v
	}
	if v, ok := four[0x0C]; ok {
		rec.Status["odometer"] = int64(v)
	}
	if v, ok := four[0x0D]; ok {
		rec.Status["runTime"] = int64(v)
	}
	if v, ok := two[0x29]; ok {
		rec.Status["fuel"] = float64(v) / 100
	}
	if v, ok := four[0x25]; ok {
		rec.Status["rfid"] = strconv.FormatUint(uint64(v), 10)
	}
	if v, ok := one[0x1B]; ok && (ev == 20 || ev == 21) {
		rec.Status["geofence"] = v
	}
	if v, ok := two[0xFE90]; ok && (ev == 20 || ev == 21) {
		rec.Status["geofence"] = v
	}
	ad := make([]float64, 5)
	hasAD := false
	for i, id := range []int{0x16, 0x17, 0x18, 0x19, 0x1A} {
		ad[i] = math.NaN()
		if v, ok := two[id]; ok {
			ad[i], hasAD = float64(v), true
		}
	}
	if hasAD {
		c.analogStatus(rec.Status, ad, true)
	}
	in, hasIn := uint32(0), false
	if v, ok := four[0x42]; ok {
		in, hasIn = v, true
	} else if v, ok := one[0x15]; ok {
		in, hasIn = uint32(v), true
	}
	out := uint32(math.MaxUint32)
	if v, ok := one[0x14]; ok {
		out = uint32(v)
	}
	if hasIn {
		c.ioStatus(rec.Status, in, out, 8)
	}
	if cell, ok := vars[0x0E]; ok && len(cell) >= 10 {
		cr := &reader{b: cell}
		mcc, mnc, lac, cid := cr.u16(), cr.u16(), cr.u16(), cr.u32()
		cl := track.Cell{MCC: mcc, MNC: mnc, LAC: lac, CID: int64(cid)}
		if len(cr.b) >= 2 {
			rssi := int(int16(cr.u16()))
			cl.RSSI = &rssi
		}
		if mcc > 0 {
			rec.Network = &track.Network{Cells: []track.Cell{cl}}
		}
	}
	rec.Alerts = c.alerts(ev, rec.Status)
	return rec, nil
}

// ---- commands ---------------------------------------------------------------

// Identifier is the data identifier of the command with sequence seq: the
// letters A to Z and a to z in turn.
func Identifier(seq uint32) byte {
	const letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	return letters[(seq+len32(letters)-1)%len32(letters)]
}

func len32(s string) uint32 { return uint32(len(s)) }

// text resolves a command's content to "<type>,<params>".
func (c *codec) text(imei string, content any) (string, error) {
	n, named, err := track.ReadNamed(content)
	if err != nil {
		return "", err
	}
	if !named {
		t, err := track.CommandText(content)
		if err != nil {
			return "", errors.New(`a Meitrack command is {"text": "<command type>,<parameters>"}, such as {"text": "A10"}`)
		}
		return t, checkText(t)
	}
	if n.Action == track.ActionInterval {
		if err := Interval.Check(n.Seconds); err != nil {
			return "", err
		}
	}
	if tmpl, set := c.cfg.named[n.Action]; set {
		if tmpl == "" {
			return "", track.Unsupported(name, n.Action, "profile.namedCommands."+n.Action+" turns it off; send the device's command as text")
		}
		t := track.Expand(tmpl, n, imei, "")
		return t, checkText(t)
	}
	switch n.Action {
	case track.ActionEngineStop, track.ActionEngineResume:
		on := n.Action == track.ActionEngineStop
		if c.cfg.inverted {
			on = !on
		}
		outs := []byte("22222")
		outs[c.cfg.relay-1] = '0'
		if on {
			outs[c.cfg.relay-1] = '1'
		}
		speed := 0
		if n.Action == track.ActionEngineStop {
			speed = c.cfg.speed
		}
		return "C01," + strconv.Itoa(speed) + "," + string(outs), nil
	case track.ActionLocate:
		return "A10", nil
	case track.ActionReboot:
		return "", track.Unsupported(name, n.Action, `the protocol restarts modules only; set profile.namedCommands.reboot to "F00,1,1" (GSM and GPS modules, T1/T333/T366) or "F01" (GSM module), or send it as text`)
	case track.ActionInterval:
		// Interval.Check (above) has refused a value off its 10 s step.
		return "A12," + strconv.Itoa(n.Seconds/10), nil
	}
	return "", track.Unsupported(name, n.Action, "")
}

// checkText refuses what would break the frame.
func checkText(t string) error {
	if len(t) > MaxCommand {
		return fmt.Errorf("a Meitrack command is at most %d characters", MaxCommand)
	}
	if strings.ContainsAny(t, "*\r\n") {
		return errors.New("a Meitrack command cannot contain '*' or a line break")
	}
	typ, _, _ := strings.Cut(t, ",")
	if !commandType(strings.ToUpper(typ)) {
		return fmt.Errorf("%q does not start with a command type such as A10 or C01", t)
	}
	return nil
}

func cmdType(t string) string {
	typ, _, _ := strings.Cut(t, ",")
	return strings.ToUpper(typ)
}

// Command frames a command with the identifier of seq; the device answers
// every documented command.
func (c *codec) Command(imei string, content any, seq uint32) ([]byte, bool, error) {
	t, err := c.text(imei, content)
	if err != nil {
		return nil, false, err
	}
	typ := cmdType(t)
	if typ != t[:3] {
		t = typ + t[3:]
	}
	return Encode(true, Identifier(seq), imei, []byte(t)), true, nil
}

// Correlation: the answer carries the command's data identifier and type.
func (c *codec) Correlation(content any, seq uint32) (string, bool) {
	t, err := c.text("", content)
	if err != nil {
		return "", false
	}
	return c.correlation(Identifier(seq), cmdType(t)), true
}
