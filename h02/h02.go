// Package h02 is the H02 tracker protocol of the Sinotrack ST-901, ST-902
// and ST-906 and the many budget two-wheeler and car trackers built on the
// same firmware: frame reading, decoding into track.Message, and command
// framing. Our own implementation from the published protocol documents:
//
//   - HuaSunTeK "GPS Tracker Communication Protocol" V1.0.5 (2017),
//     https://www.traccar.org/protocol/5013-h02/GPS+Tracker+Platform+Communication+Protocol-From+Winnie+HuaSunTeK-V1.0.5-2017.pdf
//     (frame layout, status word, V1, VP1, XT, VI1, BC, ALRM, V4 and its
//     result byte, commands S20, CR, CQ, XT/NXT)
//   - Cantrack "CANTRACK PROTOCOL" A/1 (2017),
//     https://www.traccar.org/protocol/5013-h02/h02_cantrack_secumore.pdf
//     (V2, V3 cells, HTBT, V4 with the command's time, DONE/OK/ERROR
//     results, D1 and R1, the status word, the 32-byte binary record)
//
// Traccar's H02 decoder and encoder (Apache-2.0) were read as a reference
// for behaviour seen in the field (NBR, LINK, the binary validity nibble,
// the S71 interval form); no code is taken from them.
//
// # Frames
//
// Text frames are "*HQ,<id>,<type>,…#" (any two-letter maker in place of
// HQ, either case); <id> is the IMEI or a 10-digit device number, and every
// frame carries it, so the first frame identifies the tracker (there is no
// login exchange). Handled types:
//
//	V1 V2 V5 V6 V8 V19 VI1   position: hhmmss, A|V|B, ddmm.mmmm, N|S, dddmm.mmmm, E|W, knots, course, ddmmyy, status word, …
//	VP1                      short position (no time), or cells separated by Y when the second field is V
//	BC                       positions stored while out of coverage (history), separated by ';'
//	ALRM                     alarm: 1 SOS, 2 low battery, 3 geofence, with a position
//	V3 NBR                   mobile cells (the record's track.Network)
//	LINK                     signal, satellites and battery
//	XT HTBT V0 (empty type)  heartbeat; HTBT and V0 are echoed back, as devices expect
//	V4                       answer to a command: V4,<command>[,<result>][,<command time>,<time>,<position>…]
//	SMS                      a text answer, as the device would send by SMS
//
// Any other type is skipped (track.Skip) with the warning unknownMessage. The
// binary form starts with '$' (0x24): a 32-byte record (45 bytes in a newer
// form whose last 13 bytes are not read) holding the 10-digit device
// number, time and date, latitude and longitude as packed BCD, a nibble of
// validity and hemisphere flags, speed (knots), course and the status word.
// Positions are not answered unless profile.ackPositions is set.
//
// # Status word
//
// Eight hexadecimal characters, 32 bits; both documents define each bit as
// active when it is 0 (statusActiveHigh flips that for firmware that sets
// them the other way). Counting bit 0 as the lowest bit of the word: bit 8
// door open, bit 9 armed, bit 10 ACC off (so ignition is on while bit 10 is
// inactive), bit 19 running on the backup battery, bit 27 fuel or power cut
// by the relay. Alarm bits become alerts once, when they become active
// (and again on each new connection while they stay active):
//
//	0 vibration (theft)   1 emergency (robbery)   2 over-speed   3 tamper (illegal ignition)
//	4 geofence-enter      7 geofence-exit         11 vibration   12 low-battery
//	15 over-speed         18 emergency (SOS)      19 main-power-removed   20 main-power-removed
//
// main-power-restored and low-battery-restored follow when those bits clear,
// and ignition-on / ignition-off when bit 10 changes. profile.alarmBits
// adds, replaces or turns off ("") the alert of any bit.
//
// # Commands
//
// {"text": "<command>"} is sent as "*HQ,<id>,<command>#" (or as written when
// it starts with '*'). The named commands (track.Named; DefaultNamed) map
// to the HuaSunTeK V1.0.5 document's commands:
//
//	engineStop    *HQ,<id>,S20,<hhmmss>,1,1#   (static cut: relay held)
//	engineResume  *HQ,<id>,S20,<hhmmss>,1,0#
//	locate        *HQ,<id>,CR#
//	reboot        *HQ,<id>,CQ#                 (Cantrack firmware: R1)
//	interval      *HQ,<id>,XT,<seconds>#       (5 to 3600 s while driving; Cantrack: D1, Traccar: S71,22)
//
// profile.namedCommands replaces the text after the id for firmware that
// differs; the codec puts the current UTC time after the command word of
// any numbered command (S20, S71, D1, R1, …), as both documents show, so a
// template is written without it ("D1,{seconds}" becomes
// "*HQ,<id>,D1,<hhmmss>,600#").
//
// The device answers with V4 naming the command, and for commands that carry
// a time also echoing that time. The answer completes the command; its
// result fails it when it is a hexadecimal byte below 80 (00 not done, 01
// not supported, 02 out of range, …) or holds a failure word (ERROR). An
// answer is matched to its command (the codec is a track.Correlator) by
// command word and echoed time (answerMatch "commandTime"), so a late
// answer cannot complete a later command; "command" matches by the word
// only, for firmware that does not echo the time, and "none" takes any
// answer (a server should then hold the next command until a timed-out
// command's answer came or its time passed).
//
// Many Sinotrack units send over UDP as well as TCP; a datagram may hold
// several frames, which Decode reads one after the other, and commands go
// back to the tracker's last UDP source.
//
// The profile (NewCodec; Profile):
//
//	timezone: UTC                 # zone of the device's clock (default UTC)
//	statusActiveHigh: false       # default false: status bits are active when 0, as documented
//	alarmBits: {"26": tamper}     # extra or changed status-word bits → alert type ("" turns a bit off)
//	ackPositions: false           # default false; true answers positions (V4,V1 and R12), for firmware that waits for it
//	answerMatch: commandTime      # commandTime (default), command or none
//	failureWords: [error, fail]   # default; an answer result holding one fails the command
//	marker: HQ                    # default HQ; the maker field of commands sent
//	namedCommands: {reboot: "R1", interval: "D1,{seconds}"}   # text after the id per named action ("" turns one off)
package h02

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cB-Sigma/trackers/track"
)

// Interval bounds the interval command (the V1.0.5 document's XT range).
var Interval = track.IntervalRange{Min: 5, Max: 3600}

// NamedActions are the named commands H02 has: all of them.
var NamedActions = track.Actions

// DefaultNamed are the named commands of the HuaSunTeK V1.0.5 document,
// the text after the id (the codec adds the time to numbered commands).
var DefaultNamed = map[string]string{
	track.ActionEngineStop:   "S20,1,1",
	track.ActionEngineResume: "S20,1,0",
	track.ActionLocate:       "CR",
	track.ActionReboot:       "CQ",
	track.ActionInterval:     "XT,{seconds}",
}

// Profile is the manufacturer-variation settings.
type Profile struct {
	// Timezone is the zone of the device's clock (default UTC).
	Timezone string `json:"timezone,omitempty"`
	// StatusActiveHigh (default false) reads the status word's bits as
	// active when 1, for firmware that inverts the documented polarity.
	StatusActiveHigh bool `json:"statusActiveHigh,omitempty"`
	// AlarmBits maps a status-word bit ("0" to "31") to an alert type, or
	// to "" to raise none for it; it is applied over the defaults.
	AlarmBits map[string]string `json:"alarmBits,omitempty"`
	// AckPositions (default false) answers position frames (V4,V1 for text,
	// R12 for binary), for firmware that resends until answered.
	AckPositions bool `json:"ackPositions,omitempty"`
	// AnswerMatch is how a V4 answer is matched to its command:
	// "commandTime" (default) by command word and echoed time, "command"
	// by the word only, "none" not at all.
	AnswerMatch string `json:"answerMatch,omitempty"`
	// FailureWords are the words of a V4 result that fail the command
	// (default error, fail).
	FailureWords []string `json:"failureWords,omitempty"`
	// Marker is the maker field of commands sent (default HQ).
	Marker string `json:"marker,omitempty"`
	// NamedCommands replaces the text after the id of a named command
	// (with {seconds} and {imei}); "" turns the action off.
	NamedCommands track.NamedTemplates `json:"namedCommands,omitempty"`
}

type config struct {
	loc        *time.Location
	activeHigh bool
	bits       map[int]string
	ack        bool
	match      string
	fail       []string
	marker     string
	named      track.NamedTemplates
}

var defaultBits = map[int]string{
	0: "vibration", 1: "emergency", 2: "over-speed", 3: "tamper", 4: "geofence-enter", 7: "geofence-exit",
	11: "vibration", 12: "low-battery", 15: "over-speed", 18: "emergency", 19: "main-power-removed", 20: "main-power-removed",
}

// Status-word bits read into status values.
const (
	bitDoor     = 8
	bitArmed    = 9
	bitACCOff   = 10
	bitBackup   = 19
	bitFuelCut  = 27
	bitLowBatt  = 12
	maxFrameLen = 4096
)

var markerRE = regexp.MustCompile(`^[A-Za-z]{2}$`)

// NewCodec validates a profile (empty for the defaults) and returns a
// factory of codecs, one per connection.
func NewCodec(raw json.RawMessage) (func() track.Codec, error) {
	var p Profile
	if err := track.StrictJSON(raw, &p); err != nil {
		return nil, err
	}
	c := config{loc: time.UTC, activeHigh: p.StatusActiveHigh, ack: p.AckPositions, bits: map[int]string{}, match: "commandTime", marker: "HQ"}
	if p.Timezone != "" {
		l, err := time.LoadLocation(p.Timezone)
		if err != nil {
			return nil, fmt.Errorf("timezone %q: %w", p.Timezone, err)
		}
		c.loc = l
	}
	for k, v := range defaultBits {
		c.bits[k] = v
	}
	for k, v := range p.AlarmBits {
		n, err := strconv.Atoi(k)
		if err != nil || n < 0 || n > 31 {
			return nil, fmt.Errorf("alarmBits: %q is not a bit number from 0 to 31", k)
		}
		if v == "" {
			delete(c.bits, n)
			continue
		}
		c.bits[n] = v
	}
	switch p.AnswerMatch {
	case "":
	case "commandTime", "command", "none":
		c.match = p.AnswerMatch
	default:
		return nil, fmt.Errorf(`answerMatch %q: use "commandTime", "command" or "none"`, p.AnswerMatch)
	}
	fw, err := track.FailureWords(p.FailureWords, "error", "fail")
	if err != nil {
		return nil, err
	}
	c.fail = fw
	if p.Marker != "" {
		if !markerRE.MatchString(p.Marker) {
			return nil, fmt.Errorf("marker %q: two letters, such as HQ", p.Marker)
		}
		c.marker = p.Marker
	}
	if err := p.NamedCommands.Check(false); err != nil {
		return nil, err
	}
	for k, v := range p.NamedCommands {
		if strings.ContainsAny(v, "#*") {
			return nil, fmt.Errorf("namedCommands.%s: write only the text after the id, without '*' or '#'", k)
		}
	}
	c.named = p.NamedCommands
	return func() track.Codec { return &codec{cfg: c, corr: map[uint32]string{}} }, nil
}

type codec struct {
	cfg  config
	imei string

	// Status-word state of this connection, for alerts on change.
	seen   bool
	active map[string]bool // alert type → active
	ign    bool

	mu       sync.Mutex
	corr     map[uint32]string // command sequence → correlation
	lastTime time.Time         // time put in the last numbered command
}

// ---- framing ----------------------------------------------------------------

// Binary record lengths.
const (
	binShort = 32
	binLong  = 45
)

func (c *codec) Decode(r *bufio.Reader) (*track.Message, error) {
	for {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		switch b {
		case '*':
			return c.text(r)
		case '$':
			return c.binary(r)
		}
		// Line ends and noise between frames are passed over.
	}
}

func (c *codec) text(r *bufio.Reader) (*track.Message, error) {
	line, err := r.ReadSlice('#')
	if errors.Is(err, bufio.ErrBufferFull) {
		// Drop the rest of the over-long frame and read on.
		for errors.Is(err, bufio.ErrBufferFull) {
			_, err = r.ReadSlice('#')
		}
		if err != nil {
			return nil, err
		}
		return nil, &track.Skip{Warning: track.Warning{Code: "unknownPacket", Detail: "over 4096 bytes",
			Msg: "A text frame longer than the protocol allows was passed over. Check the device's protocol setting if it keeps happening."}}
	}
	if err != nil {
		return nil, err // a frame cut off by the end of the stream ends it
	}
	s := strings.TrimSpace(strings.TrimSuffix(string(line), "#"))
	return c.sentence(s)
}

// ReadFrame reads one text frame ("*…#", returned without '*' and '#') or
// binary record ('$' and the record) from r, for simulators and tools.
func ReadFrame(r *bufio.Reader) (string, error) {
	for {
		b, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if b == '*' {
			line, err := r.ReadString('#')
			if err != nil {
				return "", err
			}
			return strings.TrimSpace(strings.TrimSuffix(line, "#")), nil
		}
	}
}

func trim(s string) string {
	if len(s) > 64 {
		return s[:64]
	}
	return s
}

func unknown(s string) error {
	return &track.Skip{Warning: track.Warning{Code: "unknownMessage", Detail: trim(s),
		Msg: "A message this codec does not read was passed over."}}
}

// sentence decodes a text frame without its '*' and '#'.
func (c *codec) sentence(s string) (*track.Message, error) {
	f := strings.Split(s, ",")
	for i := range f {
		f[i] = strings.TrimSpace(f[i])
	}
	if len(f) < 2 || !markerRE.MatchString(f[0]) {
		return nil, &track.Skip{Warning: track.Warning{Code: "unknownPacket", Detail: trim(s),
			Msg: "A frame that is not an H02 frame was passed over."}}
	}
	m := &track.Message{IMEI: f[1]}
	if m.IMEI != "" && c.imei == "" {
		m.Login = true
		c.imei = m.IMEI
	}
	typ := ""
	if len(f) > 2 {
		typ = strings.ToUpper(f[2])
	}
	m.Kind = "normal"
	switch typ {
	case "", "XT", "HTBT", "V0":
		m.Kind = "health"
		if typ == "HTBT" || typ == "V0" {
			m.Reply = []byte("*" + f[0] + "," + f[1] + "," + f[2] + "#")
		}
		return m, nil
	case "V1", "V2", "V5", "V6", "V8", "V19", "VI1":
		rec, ok := c.position(f, 3)
		if !ok {
			return nil, unknown(s)
		}
		if typ == "V19" {
			for _, x := range f[12:] {
				if len(x) >= 19 && strings.HasPrefix(x, "89") {
					rec.Status["iccid"] = strings.TrimRight(x, "?")
				}
			}
		}
		m.Records = []track.Record{rec}
		if c.cfg.ack && typ == "V1" {
			m.Reply = []byte(fmt.Sprintf("*%s,%s,V4,V1,%s#", f[0], f[1], time.Now().UTC().Format("20060102150405")))
		}
		return m, nil
	case "VP1":
		rec, ok := c.vp1(f)
		if !ok {
			return nil, unknown(s)
		}
		m.Records = []track.Record{rec}
		return m, nil
	case "ALRM":
		return c.alrm(m, f, s)
	case "BC":
		return c.blind(m, f, s)
	case "V3":
		rec, ok := c.v3(f)
		if !ok {
			return nil, unknown(s)
		}
		m.Records = []track.Record{rec}
		return m, nil
	case "NBR":
		rec, ok := c.nbr(f)
		if !ok {
			return nil, unknown(s)
		}
		m.Records = []track.Record{rec}
		m.Reply = []byte(fmt.Sprintf("*%s,%s,V4,NBR,%s#", f[0], f[1], time.Now().UTC().Format("20060102150405")))
		return m, nil
	case "LINK":
		rec, ok := c.link(f)
		if !ok {
			return nil, unknown(s)
		}
		m.Kind = "health"
		m.Records = []track.Record{rec}
		return m, nil
	case "V4":
		c.answer(m, f, s)
		return m, nil
	case "SMS":
		text := strings.SplitN(s, ",", 4)
		ans := ""
		if len(text) == 4 {
			ans = text[3]
		}
		m.Kind = "response"
		m.Response = &ans
		m.Failed = track.AnswerFailed(ans, c.cfg.fail)
		return m, nil
	}
	return nil, unknown(s)
}

// ---- fields -----------------------------------------------------------------

func digits(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < n; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func isHex8(s string) bool {
	if len(s) != 8 {
		return false
	}
	_, err := strconv.ParseUint(s, 16, 32)
	return err == nil
}

// coord reads ddmm.mmmm (dddmm.mmmm), or the same digits without the dot.
func coord(s, hemi string) (float64, bool) {
	if s == "" || strings.ContainsAny(s, "-+") {
		return 0, false
	}
	if !strings.Contains(s, ".") {
		if len(s) < 7 {
			return 0, false
		}
		s = s[:len(s)-4] + "." + s[len(s)-4:]
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	deg := math.Floor(v / 100)
	d := deg + (v-deg*100)/60
	if strings.EqualFold(hemi, "S") || strings.EqualFold(hemi, "W") {
		d = -d
	}
	return math.Round(d*1e7) / 1e7, true
}

// when combines hhmmss and ddmmyy in the device's zone; without a usable
// date or time it is now.
func (c *codec) when(hms, dmy string) time.Time {
	if !digits(hms, 6) || !digits(dmy, 6) {
		return time.Now().UTC()
	}
	n := func(s string) int { v, _ := strconv.Atoi(s); return v }
	d, mo, y := n(dmy[0:2]), n(dmy[2:4]), n(dmy[4:6])
	if d == 0 || mo == 0 || mo > 12 {
		return time.Now().UTC()
	}
	return time.Date(2000+y, time.Month(mo), d, n(hms[0:2]), n(hms[2:4]), n(hms[4:6]), 0, c.cfg.loc).UTC()
}

func knots(s string) *float64 {
	s = strings.TrimSpace(s)
	if s == "" {
		return track.F(0)
	}
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return nil
	}
	return track.F(math.Round(v*1.852*100) / 100)
}

// position reads the position fields from f[i] (time) on: time, validity,
// latitude, N|S, longitude, E|W, speed, course, then the date (the next
// ddmmyy field, some firmware put a field before it) and the status word
// (the next eight-hex-digit field).
func (c *codec) position(f []string, i int) (track.Record, bool) {
	rec := track.Record{Status: map[string]any{}}
	if len(f) < i+9 {
		return rec, false
	}
	x := &track.Fix{}
	lat, ok1 := coord(f[i+2], f[i+3])
	lon, ok2 := coord(f[i+4], f[i+5])
	date, rest := "", len(f)
	for j := i + 8; j < len(f) && j <= i+10; j++ {
		if digits(f[j], 6) {
			date, rest = f[j], j+1
			break
		}
	}
	x.Time = c.when(f[i], date)
	if ok1 && ok2 {
		x.Lat, x.Lon = lat, lon
		x.Speed = knots(f[i+6])
		if h, err := strconv.ParseFloat(f[i+7], 64); err == nil {
			x.Heading = &h
		} else if f[i+7] == "" {
			x.Heading = track.F(0)
		}
		switch strings.ToUpper(f[i+1]) {
		case "A", "B":
			x.Valid = true
		case "V":
		default: // a code instead of the validity letter (VI1, ALRM, V2)
			x.Valid = lat != 0 || lon != 0
		}
		rec.Fix = x
	}
	rec.Time = x.Time
	for j := rest; j < len(f); j++ {
		if isHex8(f[j]) {
			w, _ := strconv.ParseUint(f[j], 16, 32)
			c.status(&rec, uint32(w))
			break
		}
	}
	return rec, rec.Fix != nil || len(rec.Status) > 0
}

// vp1: VP1,A|B,lat,N,lon,E,speed,course,ddmmyy[,status] or VP1,V,cells.
func (c *codec) vp1(f []string) (track.Record, bool) {
	if len(f) < 4 {
		return track.Record{}, false
	}
	if strings.EqualFold(f[3], "V") {
		// mcc,mnc,lac,cid,level Y lac,cid,level Y …
		segs := strings.Split(strings.Join(f[4:], ","), "Y")
		net := &track.Network{}
		mcc, mnc := 0, 0
		for k, sg := range segs {
			p := strings.Split(strings.Trim(sg, ","), ",")
			if k == 0 {
				if len(p) < 4 {
					return track.Record{}, false
				}
				mcc, _ = strconv.Atoi(p[0])
				mnc, _ = strconv.Atoi(p[1])
				p = p[2:]
			}
			if len(p) < 2 {
				continue
			}
			lac, e1 := strconv.Atoi(p[0])
			cid, e2 := strconv.ParseInt(p[1], 10, 64)
			if e1 != nil || e2 != nil || (lac == 0 && cid == 0) {
				continue
			}
			net.Cells = append(net.Cells, track.Cell{MCC: mcc, MNC: mnc, LAC: lac, CID: cid})
		}
		if len(net.Cells) == 0 {
			return track.Record{}, false
		}
		return track.Record{Network: net, Time: time.Now().UTC()}, true
	}
	// No time of day: the report is real-time, so it is now.
	g := append([]string{f[0], f[1], f[2], time.Now().UTC().Format("150405")}, f[3:]...)
	rec, ok := c.position(g, 3)
	if ok && rec.Fix != nil {
		rec.Fix.Time = time.Now().UTC().Truncate(time.Second)
		rec.Time = rec.Fix.Time
	}
	return rec, ok
}

// alrm: ALRM,type,hhmmss[,position fields from the validity code on].
func (c *codec) alrm(m *track.Message, f []string, s string) (*track.Message, error) {
	if len(f) < 5 {
		return nil, unknown(s)
	}
	rec := track.Record{Status: map[string]any{}, Time: time.Now().UTC()}
	if len(f) >= 13 {
		if r, ok := c.position(f, 4); ok {
			rec = r
		}
	}
	types := map[string]string{"1": "emergency", "2": "low-battery", "3": "geofence-exit"}
	if t, ok := types[f[3]]; ok {
		if !hasAlert(rec.Alerts, t) {
			rec.Alerts = append(rec.Alerts, track.NewAlert(t, "ALRM"+f[3]))
		}
	} else {
		m.Warnings = append(m.Warnings, track.Warning{Code: "unknownMessage", Detail: trim(s),
			Msg: "An alarm of a type this codec does not know was recorded without an alert."})
	}
	m.Kind = "emergency"
	m.Records = []track.Record{rec}
	return m, nil
}

// blind: BC,hhmmss,length,segment;segment;… with each segment
// A|V,lat,N,lon,E,speed,course,DDhhmmss,status,mcc,mnc,lac,cid.
func (c *codec) blind(m *track.Message, f []string, s string) (*track.Message, error) {
	if len(f) < 6 {
		return nil, unknown(s)
	}
	body := strings.Join(f[5:], ",")
	now := time.Now().In(c.cfg.loc)
	for _, sg := range strings.Split(body, ";") {
		p := strings.Split(sg, ",")
		for i := range p {
			p[i] = strings.TrimSpace(p[i])
		}
		if len(p) < 8 || !digits(p[7], 8) {
			continue
		}
		day, _ := strconv.Atoi(p[7][0:2])
		// The segment names only the day: the latest such day not after today.
		mo := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
		if day > now.Day() {
			mo = mo.AddDate(0, -1, 0)
		}
		dmy := fmt.Sprintf("%02d%02d%02d", day, int(mo.Month()), mo.Year()%100)
		g := append([]string{p[7][2:]}, p[:7]...)
		g = append(g, dmy)
		g = append(g, p[8:]...)
		rec, ok := c.positionNoAlerts(g)
		if !ok || rec.Fix == nil {
			continue
		}
		rec.History = true
		m.Records = append(m.Records, rec)
	}
	if len(m.Records) == 0 {
		return nil, unknown(s)
	}
	return m, nil
}

// positionNoAlerts reads a stored position: its status word gives status
// values but no live alerts and does not change the connection's state.
func (c *codec) positionNoAlerts(g []string) (track.Record, bool) {
	seen, ign, active := c.seen, c.ign, c.active
	rec, ok := c.position(g, 0)
	c.seen, c.ign, c.active = seen, ign, active
	rec.Alerts = nil
	return rec, ok
}

// v3 (Cantrack): V3,hhmmss,MCCMNC,count,(lac,cid,rs,dBm)…,battery,reboot,X,ddmmyy,status.
func (c *codec) v3(f []string) (track.Record, bool) {
	if len(f) < 9 || len(f[4]) < 4 {
		return track.Record{}, false
	}
	mcc, e1 := strconv.Atoi(f[4][:3])
	mnc, e2 := strconv.Atoi(f[4][3:])
	n, e3 := strconv.Atoi(f[5])
	if e1 != nil || e2 != nil || e3 != nil || len(f) < 6+4*n+5 {
		return track.Record{}, false
	}
	net := &track.Network{}
	for k := 0; k < n; k++ {
		p := f[6+4*k:]
		lac, a := strconv.Atoi(p[0])
		cid, b := strconv.ParseInt(p[1], 10, 64)
		if a != nil || b != nil {
			continue
		}
		cell := track.Cell{MCC: mcc, MNC: mnc, LAC: lac, CID: cid}
		if dbm, err := strconv.Atoi(p[3]); err == nil && dbm < 0 {
			cell.RSSI = &dbm
		}
		net.Cells = append(net.Cells, cell)
	}
	rest := f[6+4*n:]
	rec := track.Record{Network: net, Status: map[string]any{}}
	if v, err := strconv.ParseUint(rest[0], 16, 16); err == nil && v > 0 {
		// Battery voltage: value/1024 of 5.6 V (Cantrack A/1, V3).
		rec.Status["batteryVoltage"] = math.Round(float64(v)/1024*5.6*100) / 100
	}
	date := ""
	for _, x := range rest {
		if digits(x, 6) {
			date = x
		}
		if isHex8(x) {
			w, _ := strconv.ParseUint(x, 16, 32)
			c.status(&rec, uint32(w))
		}
	}
	rec.Time = c.when(f[3], date)
	return rec, len(net.Cells) > 0
}

// nbr: NBR,hhmmss,mcc,mnc,ta,count,(lac,cid,level)…,ddmmyy,status[,battery].
func (c *codec) nbr(f []string) (track.Record, bool) {
	if len(f) < 10 {
		return track.Record{}, false
	}
	mcc, e1 := strconv.Atoi(f[4])
	mnc, e2 := strconv.Atoi(f[5])
	ta, e3 := strconv.Atoi(f[6])
	n, e4 := strconv.Atoi(f[7])
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || len(f) < 8+3*n+2 {
		return track.Record{}, false
	}
	net := &track.Network{TA: &ta}
	for k := 0; k < n; k++ {
		p := f[8+3*k:]
		lac, a := strconv.Atoi(p[0])
		cid, b := strconv.ParseInt(p[1], 10, 64)
		if a != nil || b != nil {
			continue
		}
		cell := track.Cell{MCC: mcc, MNC: mnc, LAC: lac, CID: cid}
		if dbm, err := strconv.Atoi(p[2]); err == nil && dbm < 0 {
			cell.RSSI = &dbm
		}
		net.Cells = append(net.Cells, cell)
	}
	rec := track.Record{Network: net, Status: map[string]any{}}
	date := f[8+3*n]
	rec.Time = c.when(f[3], date)
	if isHex8(f[9+3*n]) {
		w, _ := strconv.ParseUint(f[9+3*n], 16, 32)
		c.status(&rec, uint32(w))
	}
	return rec, len(net.Cells) > 0
}

// link: LINK,hhmmss,gsm,satellites,battery,steps,turnovers,ddmmyy,status.
func (c *codec) link(f []string) (track.Record, bool) {
	if len(f) < 10 {
		return track.Record{}, false
	}
	rec := track.Record{Status: map[string]any{}}
	for k, key := range map[int]string{4: "gsm", 5: "satellites", 6: "batteryLevel"} {
		if v, err := strconv.Atoi(f[k]); err == nil {
			rec.Status[key] = v
		}
	}
	rec.Time = c.when(f[3], f[9])
	if len(f) > 10 && isHex8(f[10]) {
		w, _ := strconv.ParseUint(f[10], 16, 32)
		c.status(&rec, uint32(w))
	}
	return rec, true
}

// ---- status word ------------------------------------------------------------

func hasAlert(as []track.Alert, t string) bool {
	for _, a := range as {
		if a.Type == t {
			return true
		}
	}
	return false
}

// status reads the status word into rec: status values, and alerts for
// alarm bits that became active since the connection's last word.
func (c *codec) status(rec *track.Record, w uint32) {
	act := func(bit int) bool {
		set := w&(1<<uint(bit)) != 0
		return set == c.cfg.activeHigh
	}
	if rec.Status == nil {
		rec.Status = map[string]any{}
	}
	ign := !act(bitACCOff)
	rec.Status["ignition"] = ign
	rec.Status["doorOpen"] = act(bitDoor)
	rec.Status["armed"] = act(bitArmed)
	rec.Status["fuelCut"] = act(bitFuelCut)
	rec.Status["mainPower"] = !act(bitBackup)
	rec.Status["statusWord"] = fmt.Sprintf("%08X", w)

	now := map[string]string{} // type → code of the first active bit
	bits := make([]int, 0, len(c.cfg.bits))
	for b := range c.cfg.bits {
		bits = append(bits, b)
	}
	sort.Ints(bits)
	for _, b := range bits {
		t := c.cfg.bits[b]
		if act(b) {
			if _, ok := now[t]; !ok {
				now[t] = "bit" + strconv.Itoa(b)
			}
		}
	}
	types := make([]string, 0, len(now))
	for t := range now {
		types = append(types, t)
	}
	sort.Strings(types)
	for _, t := range types {
		if !c.active[t] && !hasAlert(rec.Alerts, t) {
			rec.Alerts = append(rec.Alerts, track.NewAlert(t, now[t]))
		}
	}
	if c.seen {
		if c.active["main-power-removed"] && now["main-power-removed"] == "" {
			rec.Alerts = append(rec.Alerts, track.NewAlert("main-power-restored", ""))
		}
		if c.active["low-battery"] && now["low-battery"] == "" {
			rec.Alerts = append(rec.Alerts, track.NewAlert("low-battery-restored", ""))
		}
		if ign != c.ign {
			t := "ignition-off"
			if ign {
				t = "ignition-on"
			}
			rec.Alerts = append(rec.Alerts, track.NewAlert(t, "bit10"))
		}
	}
	c.active = map[string]bool{}
	for t := range now {
		c.active[t] = true
	}
	c.ign, c.seen = ign, true
}

// ---- binary -----------------------------------------------------------------

func bcd(b []byte) string {
	const hexd = "0123456789ABCDEF"
	out := make([]byte, 0, 2*len(b))
	for _, v := range b {
		out = append(out, hexd[v>>4], hexd[v&0x0F])
	}
	return string(out)
}

func (c *codec) binary(r *bufio.Reader) (*track.Message, error) {
	buf := make([]byte, binShort)
	buf[0] = '$'
	if _, err := io.ReadFull(r, buf[1:]); err != nil {
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, io.EOF // a record cut off by the end of the stream ends it
		}
		return nil, err
	}
	// The newer 45-byte form: 13 more bytes, when they follow at once and
	// do not start a frame.
	if r.Buffered() >= binLong-binShort {
		if nb, _ := r.Peek(1); len(nb) == 1 && nb[0] != '*' && nb[0] != '$' {
			_, _ = r.Discard(binLong - binShort)
		}
	}
	return c.decodeBinary(buf)
}

// decodeBinary decodes a 32-byte binary record ('$' first).
func (c *codec) decodeBinary(b []byte) (*track.Message, error) {
	h := bcd(b)
	id := h[2:12]
	tm, dt := h[12:18], h[18:24]
	latS := h[24:32]
	lonS := h[34:43]
	flags := b[21] & 0x0F
	if !digits(id, 10) || !digits(tm, 6) || !digits(dt, 6) || !digits(latS, 8) || !digits(lonS, 9) || !digits(h[44:50], 6) {
		return nil, &track.Skip{Warning: track.Warning{Code: "unknownPacket", Detail: h,
			Msg: "A binary record that is not packed decimal was passed over."}}
	}
	m := &track.Message{IMEI: id, Kind: "normal"}
	if c.imei == "" {
		m.Login = true
		c.imei = id
	}
	lat, _ := coord(latS[:4]+"."+latS[4:], "N")
	lon, _ := coord(lonS[:5]+"."+lonS[5:], "E")
	if flags&0x04 == 0 {
		lat = -lat
	}
	if flags&0x08 == 0 {
		lon = -lon
	}
	x := &track.Fix{Lat: lat, Lon: lon, Valid: flags&0x02 != 0, Time: c.when(tm, dt), Speed: knots(h[44:47])}
	crs, _ := strconv.Atoi(h[47:50])
	x.Heading = track.F(float64(crs))
	rec := track.Record{Fix: x, Time: x.Time, Status: map[string]any{}}
	w := uint32(b[25])<<24 | uint32(b[26])<<16 | uint32(b[27])<<8 | uint32(b[28])
	c.status(&rec, w)
	m.Records = []track.Record{rec}
	if c.cfg.ack {
		m.Reply = []byte(fmt.Sprintf("*%s,%s,R12,%s#", c.cfg.marker, id, time.Now().UTC().Format("150405")))
	}
	return m, nil
}

// ---- answers ----------------------------------------------------------------

// commandTime finds the command's echoed time in a V4 answer's fields
// after the command word: the first of two consecutive hhmmss fields
// (command time, then answer time).
func commandTime(f []string) (string, int) {
	for i := 0; i+1 < len(f); i++ {
		if digits(f[i], 6) && digits(f[i+1], 6) {
			return f[i], i
		}
	}
	return "", -1
}

func (c *codec) answer(m *track.Message, f []string, s string) {
	m.Kind = "response"
	text := s
	m.Response = &text
	cmd := ""
	if len(f) > 3 {
		cmd = strings.ToUpper(f[3])
	}
	rest := []string{}
	if len(f) > 4 {
		rest = f[4:]
	}
	result := ""
	if len(rest) > 0 && !digits(rest[0], 6) {
		result = rest[0]
	}
	det := map[string]any{"command": cmd}
	if result != "" {
		det["result"] = result
		if len(result) == 2 {
			if v, err := strconv.ParseUint(result, 16, 8); err == nil {
				m.Failed = v < 0x80
				switch v {
				case 0x00:
					det["reason"] = "the device could not carry it out"
				case 0x01:
					det["reason"] = "the device does not support it"
				case 0x02:
					det["reason"] = "a value is out of range"
				}
			}
		}
		if track.AnswerFailed(result, c.cfg.fail) {
			m.Failed = true
		}
	}
	m.Details = det
	ct, at := commandTime(rest)
	switch {
	case cmd == "": // an answer naming no command (Cantrack WKMD)
	case c.cfg.match == "commandTime":
		if ct != "" {
			m.Correlation = cmd + "," + ct
		} else {
			m.Correlation = cmd
		}
	case c.cfg.match == "command":
		m.Correlation = cmd
	}
	// The position the answer carries: from the answer time, which follows
	// the command time or stands alone before the validity letter.
	from := -1
	if at >= 0 {
		from = at + 1
	} else {
		for i := 0; i+1 < len(rest); i++ {
			if digits(rest[i], 6) && strings.Contains("AVB", strings.ToUpper(rest[i+1])) && len(rest[i+1]) == 1 {
				from = i
				break
			}
		}
	}
	if from >= 0 && len(rest) >= from+9 {
		if rec, ok := c.position(rest, from); ok && rec.Fix != nil {
			m.Records = []track.Record{rec}
		}
	}
}

// ---- commands ---------------------------------------------------------------

var numbered = regexp.MustCompile(`^[SDR][0-9]+$`)

// nextTime is the time of a numbered command: now in UTC, at least a
// second after the last one, so each command's echo names it alone.
func (c *codec) nextTime() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	t := time.Now().UTC().Truncate(time.Second)
	if !t.After(c.lastTime) {
		t = c.lastTime.Add(time.Second)
	}
	c.lastTime = t
	return t.Format("150405")
}

func (c *codec) Command(imei string, content any, seq uint32) ([]byte, bool, error) {
	var frame string
	n, isNamed, err := track.ReadNamed(content)
	if err != nil {
		return nil, false, err
	}
	if isNamed {
		body, err := track.NamedText("h02", n, c.cfg.named, DefaultNamed, Interval, imei, "")
		if err != nil {
			return nil, false, err
		}
		p := strings.Split(body, ",")
		if numbered.MatchString(strings.ToUpper(p[0])) {
			p = append([]string{p[0], c.nextTime()}, p[1:]...)
		}
		frame = "*" + c.cfg.marker + "," + imei + "," + strings.Join(p, ",") + "#"
	} else {
		text, err := track.CommandText(content)
		if err != nil {
			return nil, false, errors.New(`an H02 command is {"text": "<command>"}, such as {"text": "S26,0"}, or a named command such as {"action": "locate"}`)
		}
		if len(text) > 200 {
			return nil, false, errors.New("an H02 command is at most 200 characters")
		}
		switch {
		case strings.HasPrefix(text, "*"):
			if !strings.HasSuffix(text, "#") || strings.Count(text, "#") != 1 {
				return nil, false, errors.New("a whole H02 frame starts with '*' and ends with its only '#'")
			}
			frame = text
		case strings.Contains(text, "#"):
			return nil, false, errors.New("an H02 command cannot contain '#'; write the text after the id, such as S26,0")
		default:
			frame = "*" + c.cfg.marker + "," + imei + "," + text + "#"
		}
	}
	c.mu.Lock()
	c.corr[seq] = frameCorrelation(frame, c.cfg.match)
	c.mu.Unlock()
	return []byte(frame), true, nil
}

// frameCorrelation is the correlation the answer to a command frame
// carries: its command word, and with commandTime its time field.
func frameCorrelation(frame, match string) string {
	f := strings.Split(strings.TrimSuffix(strings.TrimPrefix(frame, "*"), "#"), ",")
	if match == "none" || len(f) < 3 {
		return ""
	}
	cmd := strings.ToUpper(strings.TrimSpace(f[2]))
	if match == "commandTime" && len(f) > 3 && digits(strings.TrimSpace(f[3]), 6) {
		return cmd + "," + strings.TrimSpace(f[3])
	}
	return cmd
}

// Correlation names the answer of the command framed with seq: its
// command word, and its time where it has one.
func (c *codec) Correlation(_ any, seq uint32) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	corr := c.corr[seq]
	delete(c.corr, seq)
	return corr, false
}
