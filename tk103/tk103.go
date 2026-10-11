// Package tk103 is the TK103 / Coban (GPS103) text tracker protocol:
// frame reading, decoding into track.Message, and command framing. Frames
// end with ';':
//
//	##,imei:<imei>,A;                 login, answered LOAD
//	<imei>;                           heartbeat, answered ON
//	imei:<imei>,<keyword>,<yyMMddHHmm local>,<phone>,F|L,<hhmmss.sss UTC>,A|V,<ddmm.mmmm>,N|S,<dddmm.mmmm>,E|W,<knots>,<heading>,…;
//
// Keywords become alerts: "help me" emergency, "low battery", "speed"
// over-speed, "stockade" geofence exit, "acc on"/"acc off" ignition,
// "ac alarm" main power removed, "sensor alarm" vibration, "door alarm"
// door open, "move" movement; "tracker" is a periodic report. Commands are
// {"text": "B"} sent as **,imei:<imei>,B; the protocol has no answer
// frame, so Command reports that none is expected and a command can only
// be known to be written, not carried out.
//
// The profile (NewCodec; Profile):
//
//	commandTerminator: ";"   # default ";"; "" sends commands without it (as Traccar does)
//	namedCommands: {interval: "C,{seconds}s"}   # replaces a named command's text
//
// Named commands (track.Named), Coban GPRS command letters: engineStop
// "J", engineResume "K", locate "B", interval "C,<seconds>s" (10 to 86400
// s). No public GPS103/Coban command list (nor Traccar's GPS103 encoder)
// gives a reboot over GPRS, so reboot has no default text; for firmware
// that has one, set profile.namedCommands.reboot to its text.
package tk103

import (
	"bufio"
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/cB-Sigma/trackers/track"
)

// Profile is the manufacturer-variation settings.
type Profile struct {
	// CommandTerminator ends a command (default ";"); some firmware takes
	// commands only without it, others only with it.
	CommandTerminator *string `json:"commandTerminator,omitempty"`
	// NamedCommands replaces the text of a named command (the part after
	// "**,imei:<imei>,"). Placeholders {seconds} and {imei}; "" turns one
	// off.
	NamedCommands track.NamedTemplates `json:"namedCommands,omitempty"`
}

// NewCodec validates a profile (empty for the defaults) and returns a
// factory of codecs, one per connection.
func NewCodec(raw json.RawMessage) (func() track.Codec, error) {
	var p Profile
	if err := track.StrictJSON(raw, &p); err != nil {
		return nil, err
	}
	term := ";"
	if p.CommandTerminator != nil {
		term = *p.CommandTerminator
		if term != ";" && term != "" {
			return nil, errors.New(`commandTerminator is ";" or ""`)
		}
	}
	if err := p.NamedCommands.Check(false); err != nil {
		return nil, err
	}
	return func() track.Codec { return &codec{term: term, named: p.NamedCommands} }, nil
}

type codec struct {
	imei, term string
	named      track.NamedTemplates
}

var keywords = map[string]string{
	"help me": "emergency", "low battery": "low-battery", "speed": "over-speed", "stockade": "geofence-exit",
	"acc on": "ignition-on", "acc off": "ignition-off", "ac alarm": "main-power-removed", "sensor alarm": "vibration",
	"move": "movement", "door alarm": "door-open",
}

func (c *codec) Decode(r *bufio.Reader) (*track.Message, error) {
	line, err := r.ReadSlice(';')
	if errors.Is(err, bufio.ErrBufferFull) {
		return nil, errors.New("tk103: frame too long")
	}
	if err != nil {
		return nil, err
	}
	s := strings.TrimSpace(strings.TrimSuffix(string(line), ";"))
	if s == "" {
		return nil, track.ErrSkip
	}
	f := strings.Split(s, ",")
	switch {
	case f[0] == "##" && len(f) >= 2 && strings.HasPrefix(f[1], "imei:"):
		c.imei = strings.TrimPrefix(f[1], "imei:")
		return &track.Message{IMEI: c.imei, Login: true, Reply: []byte("LOAD")}, nil
	case len(f) == 1 && isDigits(f[0]):
		return &track.Message{IMEI: f[0], Reply: []byte("ON")}, nil
	case strings.HasPrefix(f[0], "imei:") && len(f) >= 2:
		imei := strings.TrimPrefix(f[0], "imei:")
		if c.imei == "" {
			c.imei = imei
		}
		rec := track.Record{Status: map[string]any{}}
		if t, ok := keywords[f[1]]; ok {
			if t == "movement" {
				rec.Status["movement"] = true
			} else {
				rec.Alerts = append(rec.Alerts, track.NewAlert(t, f[1]))
				switch t {
				case "ignition-on":
					rec.Status["ignition"] = true
				case "ignition-off":
					rec.Status["ignition"] = false
				}
			}
		}
		if len(f) >= 12 && f[4] == "F" {
			rec.Fix = fix(f)
		}
		return &track.Message{IMEI: imei, Records: []track.Record{rec}}, nil
	}
	d := s
	if len(d) > 64 {
		d = d[:64]
	}
	return nil, &track.Skip{Warning: track.Warning{Code: "unknownMessage", Detail: d,
		Msg: "A message this codec does not read was passed over."}}
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

// nmea turns ddmm.mmmm (or dddmm.mmmm) into degrees.
func nmea(s, hemi string) (float64, bool) {
	v, err := strconv.ParseFloat(s, 64)
	if err != nil {
		return 0, false
	}
	deg := math.Floor(v / 100)
	d := deg + (v-deg*100)/60
	if hemi == "S" || hemi == "W" {
		d = -d
	}
	return d, true
}

func fix(f []string) *track.Fix {
	lat, ok1 := nmea(f[7], f[8])
	lon, ok2 := nmea(f[9], f[10])
	if !ok1 || !ok2 {
		return nil
	}
	x := &track.Fix{Lat: lat, Lon: lon, Valid: f[6] == "A", Time: when(f[2], f[5])}
	if kn, err := strconv.ParseFloat(f[11], 64); err == nil {
		x.Speed = track.F(math.Round(kn*1.852*100) / 100)
	}
	if len(f) > 12 {
		if h, err := strconv.ParseFloat(f[12], 64); err == nil {
			x.Heading = &h
		}
	}
	return x
}

// when combines the UTC time of day with the date of the device's local
// time stamp, picking the day that puts the two within 14 hours.
func when(local, utc string) time.Time {
	if len(local) < 6 || len(utc) < 6 {
		return time.Now().UTC()
	}
	lt, err := time.Parse("060102", local[:6])
	if err != nil {
		return time.Now().UTC()
	}
	if len(local) >= 10 {
		if t, err := time.Parse("0601021504", local[:10]); err == nil {
			lt = t
		}
	}
	tod, err := time.Parse("150405", utc[:6])
	if err != nil {
		return time.Now().UTC()
	}
	best := time.Time{}
	for _, dd := range []int{0, -1, 1} {
		d := lt.AddDate(0, 0, dd)
		t := time.Date(d.Year(), d.Month(), d.Day(), tod.Hour(), tod.Minute(), tod.Second(), 0, time.UTC)
		if best.IsZero() || math.Abs(t.Sub(lt).Hours()) < math.Abs(best.Sub(lt).Hours()) {
			best = t
		}
	}
	return best
}

func (c *codec) Command(imei string, content any, _ uint32) ([]byte, bool, error) {
	text, err := commandText(c.named, imei, content)
	if err != nil {
		return nil, false, err
	}
	if strings.ContainsAny(text, ";") {
		return nil, false, errors.New("a TK103 command cannot contain ';'")
	}
	return []byte("**,imei:" + imei + "," + text + c.term), false, nil
}
