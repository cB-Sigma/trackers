// Package osmand is the OsmAnd HTTP location protocol: reading requests
// into track.Message and answering them. It is spoken by phone tracking
// apps such as Traccar Client (Android, iOS), OsmAnd's online tracking and
// the many driver and field-staff apps that use the same simple protocol,
// and by Traccar servers forwarding their positions.
//
// The codec reads HTTP/1.x requests from a TCP (or TLS, so HTTPS) stream
// (keep-alive supported) and answers each one itself. Every request names
// its device, so each one carries Message.IMEI, and the first on a
// connection is a Login. Three request forms are read, told apart by their
// content, so one listener takes them all:
//
//   - Query or form parameters (GET with a query string, or a POST with an
//     application/x-www-form-urlencoded body, which is what Traccar Client
//     9 sends): id or deviceid, lat and lon (or location=lat,lon),
//     timestamp (Unix seconds or milliseconds, ISO 8601, or
//     "yyyy-MM-dd HH:mm:ss" in UTC), valid, speed (knots by default,
//     speedUnit), bearing or heading, altitude, accuracy (or hacc), hdop,
//     sat, batt (percent), charge, alarm, driverUniqueId, ignition, cell
//     (mcc,mnc,lac,cid[,rssi], repeatable) and wifi (mac,rssi, repeatable;
//     both become the record's track.Network). Any other parameter is kept
//     in status under "attributes".
//   - The JSON body of the older Traccar Client releases: {"device_id": …,
//     "location": {"timestamp", "coords": {latitude, longitude, speed in
//     m/s, heading, accuracy, altitude}, "battery": {level 0..1,
//     is_charging}, "event", "is_moving", "odometer", "activity", "mock",
//     "extras": {"alarm": …}}}; "location" may also be a list (batch).
//   - A Traccar server's position forwarding (forward.type json): a POST of
//     {"position": {fixTime, latitude, longitude, altitude, speed in knots,
//     course, accuracy, valid, outdated, attributes: {alarm, batteryLevel,
//     ignition, motion, odometer, sat, hdop, …}}, "device": {uniqueId,
//     name, …}}, and its event forwarding ({"event": {type, attributes},
//     "position", "device"}): an alarm event or an ignition, geofence or
//     overspeed event becomes an alert. A forwarding server carries many
//     devices, so each such request is answered with Connection: close and
//     every connection carries one device.
//
// Answers: 200 with an empty body for a request that is read; 400 for a
// request without a device id; 401 for one without the profile's token;
// 403 (Message.Reject) for a device the server refuses; 413 for a body
// over MaxBody (then the connection closes). Connection: close and
// HTTP/1.0 requests are honoured: the answer carries Connection: close
// and the connection ends after it.
//
// Alarms: alarm=sos (Traccar Client's SOS button) is "emergency"; Traccar's
// other alarm names map to the shared alert types (overspeed over-speed,
// lowBattery low-battery, powerCut main-power-removed, hardBraking
// harsh-braking, geofenceEnter geofence-enter, tow towing, accident
// impact, jamming gnss-jamming, tampering tamper, …); an alarm without a
// shared type is the alert "device-alarm" with the app's word as its code.
//
// Commands: the protocol has no way back to the phone or to the forwarding
// server, so every command, named or text, fails with track.ErrUnsupported
// and the reason.
//
// A fix older than historyAfter when it arrives (the app's queue of
// positions recorded while offline) is marked Record.History, so a late
// backlog never becomes the device's latest position.
//
// Public sources (own words here; Traccar's Java decoder was read as a
// reference for behaviour only):
//
//   - https://www.traccar.org/osmand/ (parameters, time forms, knots)
//
//   - https://github.com/traccar/traccar-client-sdk (HttpUploader.kt: the
//     form POST of Traccar Client 9, speed converted to knots, batt in
//     percent, alarm)
//
//   - https://github.com/traccar/traccar-client (main_screen.dart: the SOS
//     button sends alarm=sos)
//
//   - https://github.com/traccar/traccar/blob/master/src/test/java/org/traccar/protocol/OsmAndProtocolDecoderTest.java
//     (sample requests and JSON bodies, used as test vectors)
//
//   - https://www.traccar.org/configuration-file/ and
//     https://www.traccar.org/forward/ (forward.url, forward.type json,
//     forward.header); the JSON field names are Traccar's Position and
//     Device models (src/main/java/org/traccar/model).
//
// The profile (NewCodec; Profile):
//
//	token: ""             # shared token; when set, a request must carry it as ?token= or Authorization: Bearer (default none)
//	speedUnit: kn         # unit of the speed parameter: kn (default, Traccar Client), kmh, mps or mph
//	historyAfter: 10m     # a fix older than this on arrival is history (default 10m; 0 turns it off)
package osmand

import (
	"bufio"
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cB-Sigma/trackers/track"
)

// MaxBody is the largest request body read (64 KiB).
const MaxBody = 64 << 10

// Profile is the protocol settings.
type Profile struct {
	// Token, when set, is a shared secret every request must carry, as the
	// query or form parameter token or as Authorization: Bearer <token>;
	// a request without it is answered 401 and not read. Put it in the
	// app's server URL (https://host:5055/?token=…). Default none.
	Token string `json:"token,omitempty"`
	// SpeedUnit is the unit of the speed parameter: kn (default; Traccar
	// Client sends knots), kmh, mps or mph. Apps where the operator writes
	// the URL template (OsmAnd's online tracking) often send m/s. The JSON
	// body form is always m/s and Traccar forwarding always knots.
	SpeedUnit string `json:"speedUnit,omitempty"`
	// HistoryAfter: a fix older than this when it arrives (the app's queue
	// of positions recorded offline) is marked history (Record.History)
	// instead of being the latest position. Default 10m; 0 turns it off.
	HistoryAfter *track.Duration `json:"historyAfter,omitempty"`
}

type config struct {
	token        string
	speed        float64 // factor to km/h
	historyAfter time.Duration
	now          func() time.Time
}

var speedUnits = map[string]float64{"kn": 1.852, "kmh": 1, "mps": 3.6, "mph": 1.609344}

// NewCodec reads a Profile (empty for the defaults) and returns the maker
// of one codec per connection.
func NewCodec(raw json.RawMessage) (func() track.Codec, error) {
	var p Profile
	if err := track.StrictJSON(raw, &p); err != nil {
		return nil, err
	}
	cfg := &config{token: p.Token, speed: 1.852, historyAfter: 10 * time.Minute, now: time.Now}
	if p.SpeedUnit != "" {
		f, ok := speedUnits[p.SpeedUnit]
		if !ok {
			return nil, fmt.Errorf("speedUnit %q is not kn, kmh, mps or mph. Set the unit the app sends speed in", p.SpeedUnit)
		}
		cfg.speed = f
	}
	if p.HistoryAfter != nil {
		if *p.HistoryAfter < 0 {
			return nil, errors.New("historyAfter must not be negative. Use 0 to turn it off")
		}
		cfg.historyAfter = p.HistoryAfter.D()
	}
	return func() track.Codec { return &codec{cfg: cfg} }, nil
}

// codec is one HTTP connection.
type codec struct {
	cfg *config
	// id is the device the connection's last request named; set once a
	// request has been handed to the server (which admitted it, or the
	// connection would be closed).
	id string
	// closing ends the connection after the answer just given.
	closing bool
}

// response is a raw HTTP/1.1 answer with an empty body.
func response(code int, closeConn bool) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\nContent-Length: 0\r\n", code, http.StatusText(code))
	if code == http.StatusUnauthorized {
		b.WriteString("WWW-Authenticate: Bearer\r\n")
	}
	if closeConn {
		b.WriteString("Connection: close\r\n")
	}
	b.WriteString("\r\n")
	return []byte(b.String())
}

func (c *codec) Decode(r *bufio.Reader) (*track.Message, error) {
	if c.closing {
		return nil, io.EOF
	}
	req, err := http.ReadRequest(r)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		// The stream cannot be resynchronised after a broken request:
		// answer it on a known connection, then close.
		if c.id != "" {
			c.closing = true
			return &track.Message{Reply: response(http.StatusBadRequest, true), Warnings: []track.Warning{{Code: "unknownMessage",
				Detail: trim(err.Error()), Msg: "A request that is not HTTP was answered 400 and its connection closed; the app reconnects. Check the app's server URL."}}}, nil
		}
		return nil, fmt.Errorf("osmand: not an HTTP request: %w", err)
	}
	closeAfter := req.Close
	body, err := io.ReadAll(io.LimitReader(req.Body, MaxBody+1))
	_ = req.Body.Close()
	if err != nil || len(body) > MaxBody {
		c.closing = true
		code, why := http.StatusBadRequest, "its body could not be read"
		if err == nil {
			code, why = http.StatusRequestEntityTooLarge, fmt.Sprintf("its body is over %d bytes", MaxBody)
		}
		w := track.Warning{Code: "unknownMessage", Detail: why,
			Msg: "A request was answered " + strconv.Itoa(code) + " and its connection closed: " + why + ". Check what the app sends."}
		if c.id == "" {
			return nil, &track.Skip{Warning: w, Reply: response(code, true)}
		}
		return &track.Message{Reply: response(code, true), Warnings: []track.Warning{w}}, nil
	}
	p := c.parse(req, body)
	if p.forward {
		// A forwarding server carries many devices: one per connection.
		closeAfter = true
	}
	if closeAfter {
		c.closing = true
	}
	if c.cfg.token != "" && subtle.ConstantTimeCompare([]byte(c.cfg.token), []byte(p.token)) != 1 {
		w := track.Warning{Code: "deviceRefused", Setting: "profile.token", Detail: "no token",
			Msg: "A request without the profile's token was answered 401 and not read. Add ?token=… to the app's server URL, or clear profile.token."}
		if c.id == "" {
			// Nothing may be filed for an unauthenticated request; the
			// server writes the Skip's answer, then the connection is
			// closed.
			c.closing = true
			return nil, &track.Skip{Warning: w, Reply: response(http.StatusUnauthorized, true)}
		}
		return &track.Message{Reply: response(http.StatusUnauthorized, closeAfter), Warnings: []track.Warning{w}}, nil
	}
	if p.id == "" {
		w := track.Warning{Code: "unknownMessage", Detail: trim(req.URL.String()),
			Msg: "A request without a device id (id, deviceid or device_id) was answered 400. Set the device identifier in the app."}
		if c.id == "" {
			// The server closes a connection whose first request names
			// no device (noLogin); Reject is the answer it may send.
			c.closing = true
			return &track.Message{Reject: response(http.StatusBadRequest, true), Warnings: []track.Warning{w}}, nil
		}
		return &track.Message{Reply: response(http.StatusBadRequest, closeAfter), Warnings: []track.Warning{w}}, nil
	}
	m := &track.Message{IMEI: p.id, Login: c.id == "", Records: p.records, Warnings: p.warnings,
		Reply: response(http.StatusOK, closeAfter), Kind: p.kind,
		// The answer when the server refuses the device (not listed,
		// blocked): the app keeps the position and tries again later.
		Reject: response(http.StatusForbidden, true)}
	c.id = p.id
	return m, nil
}

// Command: neither the apps nor a forwarding server can be reached from
// here.
func (c *codec) Command(imei string, content any, seq uint32) ([]byte, bool, error) {
	n, named, err := track.ReadNamed(content)
	if err != nil {
		return nil, false, err
	}
	if named {
		return nil, false, track.Unsupported("osmand", n.Action,
			"phone tracking apps and Traccar forwarding have no command channel; change the app's settings on the phone")
	}
	return nil, false, fmt.Errorf("osmand has no commands (%w): phone tracking apps and Traccar forwarding have no command channel; change the app's settings on the phone", track.ErrUnsupported)
}

// parsed is one request read.
type parsed struct {
	id, token, kind string
	forward         bool
	records         []track.Record
	warnings        []track.Warning
}

func (p *parsed) warn(detail, msg string) {
	p.warnings = append(p.warnings, track.Warning{Code: "unknownMessage", Detail: trim(detail), Msg: msg})
}

func trim(s string) string {
	if len(s) > 120 {
		return s[:120]
	}
	return s
}

func (c *codec) parse(req *http.Request, body []byte) *parsed {
	p := &parsed{kind: "normal"}
	q := req.URL.Query()
	if h := req.Header.Get("Authorization"); len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		p.token = strings.TrimSpace(h[7:])
	}
	trimmed := bytes.TrimSpace(body)
	ct, _, _ := mime.ParseMediaType(req.Header.Get("Content-Type"))
	switch {
	case len(trimmed) == 0:
	case strings.Contains(ct, "json") || trimmed[0] == '{' || trimmed[0] == '[':
		if p.token == "" {
			p.token = q.Get("token")
		}
		c.parseJSON(p, trimmed, q)
		return p
	default:
		// A form body (Traccar Client 9 posts one), read even without its
		// content type.
		form, err := url.ParseQuery(string(trimmed))
		if err != nil {
			p.warn(string(trimmed), "A request body that is neither form parameters nor JSON was passed over; its query parameters were read.")
		}
		for k, vs := range form {
			q[k] = append(q[k], vs...)
		}
	}
	if p.token == "" {
		p.token = q.Get("token")
	}
	p.id = strings.TrimSpace(first(q, "id", "deviceid"))
	p.records = []track.Record{c.fromParams(p, q)}
	return p
}

func first(q url.Values, keys ...string) string {
	for _, k := range keys {
		if v := q.Get(k); v != "" {
			return v
		}
	}
	return ""
}

// known are the parameters read into the fix or status (or dropped).
var known = map[string]bool{"id": true, "deviceid": true, "token": true, "lat": true, "lon": true, "location": true,
	"timestamp": true, "valid": true, "speed": true, "bearing": true, "heading": true, "altitude": true, "accuracy": true,
	"hacc": true, "hdop": true, "sat": true, "batt": true, "charge": true, "alarm": true, "driverUniqueId": true,
	"ignition": true, "cell": true, "wifi": true, "notificationToken": true}

func (c *codec) fromParams(p *parsed, q url.Values) track.Record {
	rec := track.Record{Status: map[string]any{}}
	t := c.cfg.now().UTC()
	if s := q.Get("timestamp"); s != "" {
		if v, ok := parseTime(s); ok {
			t = v
		} else {
			p.warn(s, "A timestamp in a form this codec does not read was replaced by the time of arrival. Use Unix seconds or milliseconds, or ISO 8601.")
		}
	}
	rec.Time = t
	latS, lonS := q.Get("lat"), q.Get("lon")
	if loc := q.Get("location"); latS == "" && lonS == "" && loc != "" {
		if a, b, ok := strings.Cut(loc, ","); ok {
			latS, lonS = a, b
		}
	}
	num := func(key, s string) *float64 {
		if s == "" {
			return nil
		}
		v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
		if err != nil || math.IsNaN(v) || math.IsInf(v, 0) {
			p.warn(key+"="+s, "A parameter that is not a number was passed over: "+key+".")
			return nil
		}
		return &v
	}
	lat, lon := num("lat", latS), num("lon", lonS)
	if lat != nil && lon != nil {
		f := &track.Fix{Time: t, Lat: *lat, Lon: *lon, Valid: true}
		if v := q.Get("valid"); v != "" {
			f.Valid = v == "1" || strings.EqualFold(v, "true")
		}
		if s := num("speed", q.Get("speed")); s != nil && *s >= 0 {
			f.Speed = track.F(*s * c.cfg.speed)
		}
		if h := num("bearing", first(q, "bearing", "heading")); h != nil && *h >= 0 {
			f.Heading = track.F(math.Mod(*h, 360))
		}
		f.Alt = num("altitude", q.Get("altitude"))
		f.HDOP = num("hdop", q.Get("hdop"))
		if s := num("sat", q.Get("sat")); s != nil {
			f.Sats = track.I(int(*s))
		}
		c.setFix(p, &rec, f)
	} else if latS != "" || lonS != "" {
		p.warn("lat="+latS+" lon="+lonS, "A request with only one of lat and lon carried no position; its other values were read.")
	}
	if a := num("accuracy", first(q, "accuracy", "hacc")); a != nil {
		rec.Status["accuracy"] = *a
	}
	if b := num("batt", q.Get("batt")); b != nil {
		rec.Status["batteryLevel"] = *b
	}
	if s := q.Get("charge"); s != "" {
		rec.Status["charging"] = s == "1" || strings.EqualFold(s, "true")
	}
	if s := q.Get("ignition"); s != "" {
		rec.Status["ignition"] = s == "1" || strings.EqualFold(s, "true")
	}
	if s := q.Get("driverUniqueId"); s != "" {
		rec.Status["driverId"] = s
	}
	for _, a := range q["alarm"] {
		rec.Alerts = append(rec.Alerts, alerts(a)...)
	}
	if len(rec.Alerts) > 0 {
		p.kind = "emergency"
		if !hasEmergency(rec.Alerts) {
			p.kind = "alarm"
		}
	}
	net := &track.Network{}
	for _, s := range q["cell"] {
		if cl, ok := parseCell(s); ok {
			net.Cells = append(net.Cells, cl)
		} else {
			p.warn("cell="+s, "A cell parameter that is not mcc,mnc,lac,cid[,rssi] was passed over.")
		}
	}
	for _, s := range q["wifi"] {
		if ap, ok := parseWiFi(s); ok {
			net.WiFi = append(net.WiFi, ap)
		} else {
			p.warn("wifi="+s, "A wifi parameter that is not mac,rssi was passed over.")
		}
	}
	if len(net.Cells)+len(net.WiFi) > 0 {
		rec.Network = net
	}
	extra := map[string]any{}
	for k, vs := range q {
		if known[k] || len(vs) == 0 {
			continue
		}
		if !attrKey(k) || len(extra) >= 32 {
			continue
		}
		extra[k] = attrValue(vs[0])
	}
	if len(extra) > 0 {
		rec.Status["attributes"] = extra
	}
	if len(rec.Status) == 0 {
		rec.Status = nil
	}
	return rec
}

// setFix checks the coordinates and files a late fix as history.
func (c *codec) setFix(p *parsed, rec *track.Record, f *track.Fix) {
	if f.Lat < -90 || f.Lat > 90 || f.Lon < -180 || f.Lon > 180 {
		p.warn(fmt.Sprintf("%v,%v", f.Lat, f.Lon), "A position outside -90..90 latitude or -180..180 longitude was passed over; the request's other values were read.")
		return
	}
	rec.Fix = f
	if c.cfg.historyAfter > 0 && !f.Time.IsZero() && c.cfg.now().Sub(f.Time) > c.cfg.historyAfter {
		rec.History = true
	}
}

func hasEmergency(as []track.Alert) bool {
	for _, a := range as {
		if a.Type == "emergency" {
			return true
		}
	}
	return false
}

// attrKey limits the extra parameters kept to plain names.
func attrKey(k string) bool {
	if k == "" || len(k) > 32 {
		return false
	}
	for i := 0; i < len(k); i++ {
		b := k[i]
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' && i > 0 || b == '_') {
			return false
		}
	}
	return true
}

func attrValue(s string) any {
	switch strings.ToLower(s) {
	case "true":
		return true
	case "false":
		return false
	}
	if v, err := strconv.ParseFloat(s, 64); err == nil && !math.IsNaN(v) && !math.IsInf(v, 0) {
		return v
	}
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}

// parseTime reads Unix seconds or milliseconds (whole or with a fraction),
// ISO 8601 with or without a zone (UTC without), and "yyyy-MM-dd HH:mm:ss".
func parseTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if v, err := strconv.ParseFloat(s, 64); err == nil && v > 0 && !math.IsInf(v, 0) {
		if v > 1e11 { // milliseconds (1e11 s is the year 5138)
			return time.UnixMilli(int64(v)).UTC(), true
		}
		sec, frac := math.Modf(v)
		return time.Unix(int64(sec), int64(frac*1e9)).UTC(), true
	}
	for _, l := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999Z0700", "2006-01-02T15:04:05.999999999",
		"2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05.999999999Z07:00"} {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func parseCell(s string) (track.Cell, bool) {
	f := strings.Split(s, ",")
	if len(f) != 4 && len(f) != 5 {
		return track.Cell{}, false
	}
	var n [5]int64
	for i, x := range f {
		v, err := strconv.ParseInt(strings.TrimSpace(x), 10, 64)
		if err != nil {
			return track.Cell{}, false
		}
		n[i] = v
	}
	cl := track.Cell{MCC: int(n[0]), MNC: int(n[1]), LAC: int(n[2]), CID: n[3]}
	if len(f) == 5 {
		cl.RSSI = track.I(int(n[4]))
	}
	return cl, true
}

func parseWiFi(s string) (track.WiFiAP, bool) {
	mac, rs, _ := strings.Cut(s, ",")
	mac = strings.ToLower(strings.ReplaceAll(strings.TrimSpace(mac), "-", ":"))
	if len(mac) != 17 {
		return track.WiFiAP{}, false
	}
	for i := 0; i < 17; i++ {
		ch := mac[i]
		if i%3 == 2 {
			if ch != ':' {
				return track.WiFiAP{}, false
			}
		} else if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return track.WiFiAP{}, false
		}
	}
	ap := track.WiFiAP{MAC: mac}
	if rs != "" {
		v, err := strconv.Atoi(strings.TrimSpace(rs))
		if err != nil {
			return track.WiFiAP{}, false
		}
		ap.RSSI = track.I(v)
	}
	return ap, true
}

// alarmTypes maps Traccar's alarm names (Position.ALARM_*) to the shared
// alert types.
var alarmTypes = map[string]string{
	"sos": "emergency", "overspeed": "over-speed", "lowbattery": "low-battery", "lowpower": "low-battery",
	"powercut": "main-power-removed", "poweroff": "main-power-removed", "powerrestored": "main-power-restored",
	"poweron": "main-power-restored", "geofenceenter": "geofence-enter", "geofenceexit": "geofence-exit",
	"hardbraking": "harsh-braking", "hardacceleration": "harsh-acceleration", "hardcornering": "rash-turning",
	"accident": "impact", "falldown": "impact", "tow": "towing", "vibration": "vibration", "jamming": "gnss-jamming",
	"tampering": "tamper", "removing": "tamper", "fatiguedriving": "fatigue-driving",
}

// alerts reads an alarm value: one name or several separated by commas.
func alerts(v string) []track.Alert {
	var out []track.Alert
	for _, a := range strings.Split(v, ",") {
		a = strings.TrimSpace(a)
		if a == "" {
			continue
		}
		if len(a) > 32 {
			a = a[:32]
		}
		if t, ok := alarmTypes[strings.ToLower(a)]; ok {
			out = append(out, track.NewAlert(t, a))
		} else {
			out = append(out, track.NewAlert("device-alarm", a))
		}
	}
	return out
}
