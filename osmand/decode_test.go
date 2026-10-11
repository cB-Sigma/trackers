package osmand_test

import (
	"bufio"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/trackers/osmand"
	"github.com/cB-Sigma/trackers/track"
)

// The clock of the decoding tests: after every sample's time, with
// history off so samples land in location.
var now = time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)

func codec(t *testing.T, profile string) track.Codec {
	t.Helper()
	if profile == "" {
		profile = `{"historyAfter": "0s"}`
	}
	c, err := osmand.NewCodecAt([]byte(profile), now)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func get(path string) string { return "GET " + path + " HTTP/1.1\r\nHost: demo\r\n\r\n" }

func post(ct, body string) string {
	return "POST / HTTP/1.1\r\nHost: demo\r\nContent-Type: " + ct + "\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
}

func decode(t *testing.T, c track.Codec, req string) *track.Message {
	t.Helper()
	m, err := c.Decode(bufio.NewReader(strings.NewReader(req)))
	if err != nil {
		t.Fatalf("decode %q: %v", req, err)
	}
	return m
}

func near(p *float64, v float64) bool { return p != nil && math.Abs(*p-v) < 1e-6 }

func statusLine(b []byte) string { s, _, _ := strings.Cut(string(b), "\r\n"); return s }

// Sample requests of Traccar's OsmAnd page (traccar.org/osmand) and of
// Traccar's OsmAndProtocolDecoderTest: positions, the time forms, speed in
// knots, cells and WiFi, extra parameters; a request without an id is
// answered 400.
//
// Covers: SIG-IMP-042
func TestDecodeDocumentedRequests(t *testing.T) {
	t.Run("iso time, knots, battery", func(t *testing.T) {
		m := decode(t, codec(t, ""), get("/?deviceid=12345&lat=48.8566&lon=2.3522&timestamp=2021-01-01T00:00:00Z&speed=15&bearing=270&altitude=35&accuracy=10&hdop=0.8&batt=75"))
		if m.IMEI != "12345" || !m.Login || statusLine(m.Reply) != "HTTP/1.1 200 OK" {
			t.Fatalf("message %+v reply %q", m, m.Reply)
		}
		r := m.Records[0]
		f := r.Fix
		if f == nil || f.Lat != 48.8566 || f.Lon != 2.3522 || !f.Time.Equal(time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)) ||
			!near(f.Speed, 15*1.852) || !near(f.Heading, 270) || !near(f.Alt, 35) || !near(f.HDOP, 0.8) || r.History {
			t.Fatalf("fix %+v", f)
		}
		if r.Status["batteryLevel"] != 75.0 || r.Status["accuracy"] != 10.0 {
			t.Fatalf("status %v", r.Status)
		}
	})
	t.Run("milliseconds", func(t *testing.T) {
		f := decode(t, codec(t, ""), get("/?id=902064&lat=42.06288&lon=-88.23412&timestamp=1442068686579&hdop=6.0&altitude=224.0&speed=0.0")).Records[0].Fix
		if !f.Time.Equal(time.UnixMilli(1442068686579)) || f.Lon != -88.23412 || !near(f.Speed, 0) {
			t.Fatalf("fix %+v", f)
		}
	})
	t.Run("escaped iso", func(t *testing.T) {
		f := decode(t, codec(t, ""), get("/?id=902064&lat=42.06288&lon=-88.23412&timestamp=2016-01-27T18%3A55%3A47Z&hdop=6.0&altitude=224.0&speed=0.0")).Records[0].Fix
		if !f.Time.Equal(time.Date(2016, 1, 27, 18, 55, 47, 0, time.UTC)) {
			t.Fatalf("time %v", f.Time)
		}
	})
	t.Run("date and time with a space", func(t *testing.T) {
		m := decode(t, codec(t, ""), get("/?lat=49.60688&lon=6.15788&timestamp=2014-06-04+09%3A10%3A11&altitude=384.7&speed=0.0&id=353861053849681"))
		if m.IMEI != "353861053849681" || !m.Records[0].Fix.Time.Equal(time.Date(2014, 6, 4, 9, 10, 11, 0, time.UTC)) {
			t.Fatalf("message %+v", m.Records[0].Fix)
		}
	})
	t.Run("seconds and location pair", func(t *testing.T) {
		f := decode(t, codec(t, ""), get("/?id=123456&timestamp=1377177267&location=60.0,30.0")).Records[0].Fix
		if f.Lat != 60 || f.Lon != 30 || !f.Time.Equal(time.Unix(1377177267, 0)) {
			t.Fatalf("fix %+v", f)
		}
	})
	t.Run("heading, hacc, no time", func(t *testing.T) {
		r := decode(t, codec(t, ""), get("/?lat=60.0&lon=30.0&speed=0.0&heading=0.0&vacc=0&hacc=0&altitude=0&deviceid=123456")).Records[0]
		if !r.Fix.Time.Equal(now) || !near(r.Fix.Heading, 0) || r.Status["accuracy"] != 0.0 {
			t.Fatalf("record %+v %v", r.Fix, r.Status)
		}
		if a := r.Status["attributes"].(map[string]any); a["vacc"] != 0.0 {
			t.Fatalf("attributes %v", a)
		}
	})
	t.Run("cells and wifi", func(t *testing.T) {
		r := decode(t, codec(t, ""), get("/?id=123456&timestamp=1377177267&cell=257,02,16,2224&cell=257,02,16,2223,-90&wifi=00-14-22-01-23-45,-80&wifi=00-1C-B3-09-85-15,-70")).Records[0]
		n := r.Network
		if r.Fix != nil || n == nil || len(n.Cells) != 2 || n.Cells[0].MCC != 257 || n.Cells[0].MNC != 2 || n.Cells[1].CID != 2223 ||
			*n.Cells[1].RSSI != -90 || len(n.WiFi) != 2 || n.WiFi[1].MAC != "00:1c:b3:09:85:15" || *n.WiFi[0].RSSI != -80 {
			t.Fatalf("network %+v", n)
		}
	})
	t.Run("ignition and extra parameters", func(t *testing.T) {
		r := decode(t, codec(t, ""), get("/?id=123456789012345&timestamp=1504763810&lat=40.7232948571&lon=-74.0061408571&bearing=7.19889788244&speed=40&ignition=true&rpm=933&fuel=24")).Records[0]
		a := r.Status["attributes"].(map[string]any)
		if r.Status["ignition"] != true || a["rpm"] != 933.0 || a["fuel"] != 24.0 || !near(r.Fix.Speed, 40*1.852) {
			t.Fatalf("record %+v %v", r.Fix, r.Status)
		}
	})
	t.Run("no id", func(t *testing.T) {
		c := codec(t, "")
		m := decode(t, c, get("/?timestamp=1377177267&lat=60.0&lon=30.0"))
		if m.IMEI != "" || statusLine(m.Reject) != "HTTP/1.1 400 Bad Request" || len(m.Warnings) != 1 {
			t.Fatalf("message %+v", m)
		}
		if _, err := c.Decode(bufio.NewReader(strings.NewReader(get("/?id=1")))); !errors.Is(err, io.EOF) {
			t.Fatalf("the connection was not closed: %v", err)
		}
	})
}

// The form POST of Traccar Client 9 (traccar-client-sdk HttpUploader) as
// the simulator sends it, its SOS alarm, and the older Traccar Client's
// JSON bodies from Traccar's decoder tests (speed m/s, battery 0..1).
//
// Covers: SIG-IMP-042
func TestDecodeClientForms(t *testing.T) {
	t.Run("form post with sos", func(t *testing.T) {
		v := "id=4321&lat=12.9716&lon=77.5946&timestamp=1759660000&accuracy=8.5&altitude=920.0&speed=10.0&bearing=90.0&batt=64&charge=true&alarm=sos"
		m := decode(t, codec(t, ""), post("application/x-www-form-urlencoded", v))
		r := m.Records[0]
		if m.IMEI != "4321" || m.Kind != "emergency" || !near(r.Fix.Speed, 18.52) || r.Status["charging"] != true || r.Status["batteryLevel"] != 64.0 {
			t.Fatalf("message %+v %+v %v", m, r.Fix, r.Status)
		}
		if len(r.Alerts) != 1 || r.Alerts[0].Type != "emergency" || r.Alerts[0].Severity != track.Critical || r.Alerts[0].Code != "sos" {
			t.Fatalf("alerts %+v", r.Alerts)
		}
	})
	t.Run("json with speed and battery", func(t *testing.T) {
		body := `{"location":{"event":"motionchange","is_moving":false,"uuid":"0e9a2473-a9a7-4c00-997b-fb97d2154e75","timestamp":"2021-07-21T08:06:34.444Z","odometer":0,"coords":{"latitude":-6.1148096,"longitude":106.6837015,"accuracy":3.8,"speed":18.67,"speed_accuracy":0.26,"heading":63,"heading_accuracy":0.28,"altitude":35.7,"altitude_accuracy":3.8},"activity":{"type":"still","confidence":100},"battery":{"is_charging":false,"level":0.79},"extras":{}},"device_id":"8737767034"}`
		m := decode(t, codec(t, ""), post("application/json", body))
		r := m.Records[0]
		if m.IMEI != "8737767034" || r.Fix.Lat != -6.1148096 || !near(r.Fix.Speed, 18.67*3.6) || !near(r.Fix.Heading, 63) ||
			!r.Fix.Time.Equal(time.Date(2021, 7, 21, 8, 6, 34, 444e6, time.UTC)) {
			t.Fatalf("message %+v %+v", m, r.Fix)
		}
		if r.Status["batteryLevel"] != 79.0 || r.Status["charging"] != false || r.Status["activity"] != "still" || r.Status["event"] != "motionchange" {
			t.Fatalf("status %v", r.Status)
		}
	})
	t.Run("json with unknown values", func(t *testing.T) {
		body := `{"location":{"extras":{},"mock":true,"coords":{"speed_accuracy":-1,"speed":-1,"longitude":-122.406417,"ellipsoidal_altitude":0,"floor":null,"heading_accuracy":-1,"latitude":37.785834000000001,"accuracy":5,"altitude_accuracy":-1,"altitude":0,"heading":-1},"is_moving":false,"age":188,"odometer":0,"uuid":"2FB04C65-99CF-42AB-8DD3-EBCB4B108BF8","event":"motionchange","battery":{"level":-1,"is_charging":false},"activity":{"type":"unknown","confidence":100},"timestamp":"2025-05-09T04:11:30.579Z"},"device_id":"658765"}`
		r := decode(t, codec(t, ""), post("application/json", body)).Records[0]
		if r.Fix.Speed != nil || r.Fix.Heading != nil || r.Status["batteryLevel"] != nil || r.Status["mockLocation"] != true {
			t.Fatalf("record %+v %v", r.Fix, r.Status)
		}
	})
	t.Run("json alarm in extras", func(t *testing.T) {
		body := `{"location":{"timestamp":"2026-10-05T11:59:00.000Z","coords":{"latitude":28.6,"longitude":77.2,"speed":5},"extras":{"alarm":"overspeed","trip":"T7"}},"device_id":"77"}`
		r := decode(t, codec(t, ""), post("application/json", body)).Records[0]
		if len(r.Alerts) != 1 || r.Alerts[0].Type != "over-speed" || r.Status["attributes"].(map[string]any)["trip"] != "T7" {
			t.Fatalf("record %+v %v", r.Alerts, r.Status)
		}
	})
	t.Run("alarm names", func(t *testing.T) {
		r := decode(t, codec(t, ""), get("/?id=1&alarm=powerCut,hardBraking,tampering,somethingNew")).Records[0]
		var types []string
		for _, a := range r.Alerts {
			types = append(types, a.Type+"/"+a.Code)
		}
		if strings.Join(types, " ") != "main-power-removed/powerCut harsh-braking/hardBraking tamper/tampering device-alarm/somethingNew" {
			t.Fatalf("alerts %v", types)
		}
	})
}

// Speed units of the profile, late fixes to history, and bad profiles.
//
// Covers: SIG-IMP-042
func TestProfile(t *testing.T) {
	for unit, kmh := range map[string]float64{"kn": 18.52, "kmh": 10, "mps": 36, "mph": 16.09344} {
		f := decode(t, codec(t, `{"speedUnit": "`+unit+`", "historyAfter": "0s"}`), get("/?id=1&lat=1&lon=2&speed=10")).Records[0].Fix
		if !near(f.Speed, kmh) {
			t.Fatalf("%s: speed %v", unit, *f.Speed)
		}
	}
	c := codec(t, `{}`)
	old := decode(t, c, get("/?id=1&lat=1&lon=2&timestamp="+strconv.FormatInt(now.Add(-time.Hour).Unix(), 10))).Records[0]
	fresh := decode(t, c, get("/?id=1&lat=1&lon=2&timestamp="+strconv.FormatInt(now.Add(-time.Minute).Unix(), 10))).Records[0]
	if !old.History || fresh.History {
		t.Fatalf("history %v %v", old.History, fresh.History)
	}
	for _, bad := range []string{`{"speedUnit": "kph"}`, `{"historyAfter": "-1m"}`, `{"tokn": "x"}`} {
		if _, err := osmand.NewCodec([]byte(bad)); err == nil {
			t.Errorf("profile %s accepted", bad)
		}
	}
}

// Lenient reading: values that cannot be read are passed over with a
// warning, the rest of the request is kept, and the session reads on.
//
// Covers: SIG-IMP-043
func TestLenient(t *testing.T) {
	c := codec(t, "")
	br := bufio.NewReader(strings.NewReader(get("/?id=9&lat=abc&lon=2&batt=50&cell=1,2&timestamp=yesterday") + get("/?id=9&lat=91.5&lon=2") + get("/?id=9&lat=1&lon=2")))
	m, err := c.Decode(br)
	if err != nil || m.Records[0].Fix != nil || m.Records[0].Status["batteryLevel"] != 50.0 || len(m.Warnings) != 4 {
		t.Fatalf("first %+v %v", m, err)
	}
	for _, w := range m.Warnings {
		if w.Code != "unknownMessage" {
			t.Fatalf("warning %+v", w)
		}
	}
	m, err = c.Decode(br)
	if err != nil || m.Records[0].Fix != nil || len(m.Warnings) != 1 || m.Login {
		t.Fatalf("second %+v %v", m, err)
	}
	if m, err = c.Decode(br); err != nil || m.Records[0].Fix == nil {
		t.Fatalf("third %+v %v", m, err)
	}
	if _, err = c.Decode(br); !errors.Is(err, io.EOF) {
		t.Fatalf("end %v", err)
	}
	// A body over 64 KiB is answered 413 and the connection closes.
	c = codec(t, "")
	decode(t, c, get("/?id=9"))
	big := post("application/x-www-form-urlencoded", "id=9&x="+strings.Repeat("a", osmand.MaxBody))
	m = decode(t, c, big)
	if statusLine(m.Reply) != "HTTP/1.1 413 Request Entity Too Large" || !strings.Contains(string(m.Reply), "Connection: close") {
		t.Fatalf("reply %q", m.Reply)
	}
	// Not HTTP at all on a new connection: the connection is closed.
	if _, err := codec(t, "").Decode(bufio.NewReader(strings.NewReader("\x78\x78\x11\x01garbage\r\n\r\n"))); err == nil || errors.Is(err, track.ErrSkip) {
		t.Fatalf("garbage: %v", err)
	}
}
