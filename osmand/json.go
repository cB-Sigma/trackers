package osmand

import (
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"strings"

	"github.com/cB-Sigma/trackers/track"
)

// The JSON request bodies: the older Traccar Client's location upload and
// a Traccar server's position and event forwarding.

func (c *codec) parseJSON(p *parsed, body []byte, q url.Values) {
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		p.warn(string(body), "A JSON request body that could not be read was passed over: "+err.Error()+".")
		p.id = strings.TrimSpace(first(q, "id", "deviceid"))
		return
	}
	obj, _ := doc.(map[string]any)
	if obj == nil {
		p.warn(string(body), "A JSON request body that is not an object was passed over.")
		p.id = strings.TrimSpace(first(q, "id", "deviceid"))
		return
	}
	if pos, ok := obj["position"].(map[string]any); ok {
		c.forwarded(p, obj, pos)
		return
	}
	p.id = strings.TrimSpace(str(obj["device_id"]))
	if p.id == "" {
		p.id = strings.TrimSpace(first(q, "id", "deviceid"))
	}
	var locs []any
	switch l := obj["location"].(type) {
	case map[string]any:
		locs = []any{l}
	case []any:
		locs = l
	default:
		p.warn(trim(string(body)), "A JSON request without a location object was passed over.")
	}
	for _, l := range locs {
		if m, ok := l.(map[string]any); ok {
			p.records = append(p.records, c.clientLocation(p, m))
		}
	}
	setKind(p)
}

func setKind(p *parsed) {
	for _, r := range p.records {
		if len(r.Alerts) == 0 {
			continue
		}
		if hasEmergency(r.Alerts) {
			p.kind = "emergency"
			return
		}
		p.kind = "alarm"
	}
}

// clientLocation is one location of the older Traccar Client: speed in
// m/s, battery level 0..1, -1 for a value the phone does not know.
func (c *codec) clientLocation(p *parsed, l map[string]any) track.Record {
	rec := track.Record{Status: map[string]any{}, Time: c.cfg.now().UTC()}
	if s := str(l["timestamp"]); s != "" {
		if t, ok := parseTime(s); ok {
			rec.Time = t
		} else {
			p.warn(s, "A timestamp in a form this codec does not read was replaced by the time of arrival.")
		}
	}
	coords, _ := l["coords"].(map[string]any)
	lat, okLat := num(coords["latitude"])
	lon, okLon := num(coords["longitude"])
	if okLat && okLon {
		f := &track.Fix{Time: rec.Time, Lat: lat, Lon: lon, Valid: true}
		if v, ok := num(coords["speed"]); ok && v >= 0 {
			f.Speed = track.F(v * 3.6)
		}
		if v, ok := num(coords["heading"]); ok && v >= 0 {
			f.Heading = track.F(math.Mod(v, 360))
		}
		if v, ok := num(coords["altitude"]); ok {
			f.Alt = track.F(v)
		}
		c.setFix(p, &rec, f)
	}
	if v, ok := num(coords["accuracy"]); ok && v >= 0 {
		rec.Status["accuracy"] = v
	}
	if b, ok := l["battery"].(map[string]any); ok {
		if v, ok := num(b["level"]); ok && v >= 0 {
			rec.Status["batteryLevel"] = math.Round(v*1000) / 10
		}
		if v, ok := b["is_charging"].(bool); ok {
			rec.Status["charging"] = v
		}
	}
	if v, ok := l["is_moving"].(bool); ok {
		rec.Status["movement"] = v
	}
	if v, ok := num(l["odometer"]); ok {
		rec.Status["odometer"] = v
	}
	if s := str(l["event"]); s != "" {
		rec.Status["event"] = s
	}
	if a, ok := l["activity"].(map[string]any); ok {
		if s := str(a["type"]); s != "" {
			rec.Status["activity"] = s
		}
	}
	if v, ok := l["mock"].(bool); ok {
		// A mock location is set by an app on the phone, not measured.
		rec.Status["mockLocation"] = v
	}
	if s := str(l["alarm"]); s != "" {
		rec.Alerts = append(rec.Alerts, alerts(s)...)
	}
	if ex, ok := l["extras"].(map[string]any); ok {
		extra := map[string]any{}
		for k, v := range ex {
			if k == "alarm" {
				if s := str(v); s != "" {
					rec.Alerts = append(rec.Alerts, alerts(s)...)
				}
				continue
			}
			if attrKey(k) && len(extra) < 32 {
				if v := scalar(v); v != nil {
					extra[k] = v
				}
			}
		}
		if len(extra) > 0 {
			rec.Status["attributes"] = extra
		}
	}
	if len(rec.Status) == 0 {
		rec.Status = nil
	}
	return rec
}

// forwarded is a Traccar server's position or event forwarding: speed in
// knots, times as ISO 8601, the device's unique id as identity.
func (c *codec) forwarded(p *parsed, obj, pos map[string]any) {
	p.forward = true
	p.kind = "forward"
	if d, ok := obj["device"].(map[string]any); ok {
		p.id = strings.TrimSpace(str(d["uniqueId"]))
	}
	rec := track.Record{Status: map[string]any{}, Time: c.cfg.now().UTC()}
	ts := str(pos["fixTime"])
	if ts == "" {
		ts = str(pos["deviceTime"])
	}
	if ts != "" {
		if t, ok := parseTime(ts); ok {
			rec.Time = t
		} else {
			p.warn(ts, "A forwarded position time in a form this codec does not read was replaced by the time of arrival.")
		}
	}
	attrs, _ := pos["attributes"].(map[string]any)
	ev, isEvent := obj["event"].(map[string]any)
	lat, okLat := num(pos["latitude"])
	lon, okLon := num(pos["longitude"])
	outdated, _ := pos["outdated"].(bool)
	// An event repeats a position already forwarded; an outdated position
	// is the last known one, not a new fix.
	if okLat && okLon && !outdated && !isEvent {
		f := &track.Fix{Time: rec.Time, Lat: lat, Lon: lon, Valid: true}
		if v, ok := pos["valid"].(bool); ok {
			f.Valid = v
		}
		if v, ok := num(pos["speed"]); ok && v >= 0 {
			f.Speed = track.F(v * 1.852)
		}
		if v, ok := num(pos["course"]); ok && v >= 0 {
			f.Heading = track.F(math.Mod(v, 360))
		}
		if v, ok := num(pos["altitude"]); ok {
			f.Alt = track.F(v)
		}
		if v, ok := num(attrs["sat"]); ok {
			f.Sats = track.I(int(v))
		}
		if v, ok := num(attrs["hdop"]); ok {
			f.HDOP = track.F(v)
		}
		c.setFix(p, &rec, f)
	}
	if v, ok := num(pos["accuracy"]); ok && v > 0 {
		rec.Status["accuracy"] = v
	}
	// Traccar attribute names to ours.
	for from, to := range map[string]string{"batteryLevel": "batteryLevel", "ignition": "ignition", "motion": "movement",
		"odometer": "odometer", "totalDistance": "totalDistance", "power": "externalVoltage", "battery": "batteryVoltage",
		"rssi": "rssi", "charge": "charging", "driverUniqueId": "driverId", "fuel": "fuel"} {
		if v := scalar(attrs[from]); v != nil {
			rec.Status[to] = v
		}
	}
	if isEvent {
		typ := str(ev["type"])
		evAttrs, _ := ev["attributes"].(map[string]any)
		switch typ {
		case "alarm":
			if s := str(evAttrs["alarm"]); s != "" {
				rec.Alerts = append(rec.Alerts, alerts(s)...)
			}
		case "ignitionOn":
			rec.Alerts = append(rec.Alerts, track.NewAlert("ignition-on", typ))
		case "ignitionOff":
			rec.Alerts = append(rec.Alerts, track.NewAlert("ignition-off", typ))
		case "geofenceEnter":
			rec.Alerts = append(rec.Alerts, track.NewAlert("geofence-enter", typ))
		case "geofenceExit":
			rec.Alerts = append(rec.Alerts, track.NewAlert("geofence-exit", typ))
		case "deviceOverspeed":
			rec.Alerts = append(rec.Alerts, track.NewAlert("over-speed", typ))
		default:
			if typ != "" {
				rec.Status["event"] = typ
			}
		}
	} else if s := str(attrs["alarm"]); s != "" {
		rec.Alerts = append(rec.Alerts, alerts(s)...)
	}
	if len(rec.Status) == 0 {
		rec.Status = nil
	}
	p.records = []track.Record{rec}
	if p.kind == "forward" && len(rec.Alerts) > 0 {
		setKind(p)
	}
}

func num(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, !math.IsNaN(x) && !math.IsInf(x, 0)
	case string:
		if x == "" {
			return 0, false
		}
		var f float64
		if _, err := fmt.Sscan(x, &f); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
			return f, true
		}
	}
	return 0, false
}

func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return fmt.Sprint(x)
	}
	return ""
}

// scalar keeps a bool, a number or a short string.
func scalar(v any) any {
	switch x := v.(type) {
	case bool, float64:
		return x
	case string:
		if len(x) > 64 {
			return x[:64]
		}
		return x
	}
	return nil
}
