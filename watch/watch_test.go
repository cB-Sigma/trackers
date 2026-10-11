// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package watch_test

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/trackers/track"
	"github.com/cB-Sigma/trackers/watch"
)

// Frames marked "doc" are the examples of the 3G watch "Communication
// Protocol" V1.7_C; the others are from Traccar's WatchProtocolDecoderTest,
// WatchFrameDecoderTest and WatchProtocolEncoderTest (Apache-2.0), used as
// test vectors only.

func newCodec(t *testing.T, profile string) track.Codec {
	t.Helper()
	nc, err := watch.NewCodec(json.RawMessage(profile))
	if err != nil {
		t.Fatal(err)
	}
	return nc()
}

func decode(t *testing.T, c track.Codec, s string) *track.Message {
	t.Helper()
	m, err := c.Decode(bufio.NewReader(strings.NewReader(s)))
	if err != nil {
		t.Fatalf("%s: %v", s, err)
	}
	return m
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-6 }

// The link keep-alive (doc) is the login and is answered LK, with the
// device's vendor, ID and index form.
func TestLink(t *testing.T) {
	c := newCodec(t, "")
	m := decode(t, c, "[SG*8800000015*0002*LK]")
	if !m.Login || m.IMEI != "8800000015" || string(m.Reply) != "[SG*8800000015*0002*LK]" || m.Kind != "link" {
		t.Fatalf("%+v %q", m, m.Reply)
	}
	m = decode(t, c, "[3G*4700186508*000B*LK,0,10,100]")
	st := m.Records[0].Status
	if m.Login || string(m.Reply) != "[3G*4700186508*0002*LK]" || st["steps"] != 0 || st["rolls"] != 10 || st["batteryLevel"] != 100 {
		t.Fatalf("%+v %v", m, st)
	}
	m = decode(t, newCodec(t, ""), "[ZJ*014111001350304*0034*0009*LK,0,0,19]")
	if string(m.Reply) != "[ZJ*014111001350304*0034*0002*LK]" {
		t.Fatalf("%q", m.Reply)
	}
}

// A position (doc): time, fix, speed, altitude, satellites, GSM,
// battery, steps and four cells; not answered. UD2 is history.
func TestPosition(t *testing.T) {
	c := newCodec(t, "")
	const body = ",220414,134652,A,22.571707,N,113.8613968,E,0.1,0.0,100,7,60,90,1000,50,0000,4,1,460,0,9360,4082,131,9360,4092,148,9360,4091,143,9360,4153,141]"
	m := decode(t, c, "[SG*8800000015*0087*UD"+body)
	if m.Reply != nil || len(m.Records) != 1 {
		t.Fatalf("%+v", m)
	}
	r := m.Records[0]
	f := r.Fix
	if !f.Valid || !f.Time.Equal(time.Date(2014, 4, 22, 13, 46, 52, 0, time.UTC)) || !near(f.Lat, 22.571707) || !near(f.Lon, 113.8613968) ||
		*f.Speed != 0.1 || *f.Alt != 100 || *f.Sats != 7 || r.History {
		t.Fatalf("%+v", f)
	}
	if r.Status["gsm"] != 60 || r.Status["batteryLevel"] != 90 || r.Status["steps"] != 1000 || len(r.Network.Cells) != 4 ||
		r.Network.Cells[0].MCC != 460 || r.Network.Cells[0].LAC != 9360 || r.Network.Cells[0].CID != 4082 || len(r.Alerts) != 0 {
		t.Fatalf("%v %+v", r.Status, r.Network)
	}
	if m := decode(t, c, "[SG*8800000015*0088*UD2"+body); !m.Records[0].History {
		t.Fatal("UD2 is not history")
	}
	// Speed in miles per hour, as the document states, by profile.
	m = decode(t, newCodec(t, `{"speedUnit": "mph"}`), "[SG*8800000015*0087*UD,220414,134652,A,22.571707,N,113.8613968,E,10,0.0,100,7,60,90,1000,50,0000,0]")
	if !near(*m.Records[0].Fix.Speed, 16.09344) {
		t.Fatalf("%v", *m.Records[0].Fix.Speed)
	}
}

// Variants: hexadecimal cell numbers, signed coordinates, empty
// hemispheres, WiFi lists, a padded longitude, LTE type names.
func TestPositionVariants(t *testing.T) {
	c := newCodec(t, "")
	m := decode(t, c, "[SG*9059011020*0067*AL,240123,181628,V,54.427538,N,6.409275,W,0.00,0,0,0,19,90,0,0,00000000,1,1,234,10,55C0,3B882A2,132,,10]")
	r := m.Records[0]
	if r.Fix.Valid || !near(r.Fix.Lon, -6.409275) || r.Network.Cells[0].LAC != 0x55C0 || r.Network.Cells[0].CID != 0x3B882A2 || string(m.Reply) != "[SG*9059011020*0002*AL]" {
		t.Fatalf("%+v %+v %q", r.Fix, r.Network, m.Reply)
	}
	m = decode(t, c, "[3G*6105117105*008D*UD2,210716,231601,V,-33.480366,N,-70.7630692,E,0.00,0.0,0.0,0,100,34,0,0,00000000,3,255,730,2,29731,54315,167,29731,54316,162,29731,54317,145]")
	if f := m.Records[0].Fix; !near(f.Lat, -33.480366) || !near(f.Lon, -70.7630692) {
		t.Fatalf("%+v", f)
	}
	m = decode(t, c, "[3G*8800000015*00DD*UD,010120,025946,V,0.0,N,0.0,E,22.0,0,-1,0,100,98,0,0,00000000,0,5,eduroam,f4:db:e6:d2:a8:00,-53,eduroam,f4:db:e6:da:d0:80,-79,eduroam,78:0c:f0:24:f9:80,-82,Lions,b0:be:76:0a:05:9a,-82,tubs-guest,f4:db:e6:d2:a8:01,-53,0.0]")
	if nw := m.Records[0].Network; nw == nil || len(nw.WiFi) != 5 || nw.WiFi[0].MAC != "f4:db:e6:d2:a8:00" || *nw.WiFi[0].RSSI != -53 {
		t.Fatalf("%+v", nw)
	}
	m = decode(t, c, "[3G*4700222306*0077*UD,120316,140610,V,48.779045,N, 9.1574736,E,0.00,0.0,0.0,0,25,83,0,0,00000000,2,255,262,1,21041,9067,121,21041,5981,116]")
	if !near(m.Records[0].Fix.Lon, 9.1574736) {
		t.Fatalf("%+v", m.Records[0].Fix)
	}
	m = decode(t, c, "[3G*2104326058*00E9*UD_LTE,300621,135101,A,32.162652,N,34.888748,E,30.84,265.158,65.621,18,100,83,0,0,00000000,1,1,425,01,10223,8012811,100,3,ES4104,22:74:1d:39:64:ff,-46,metropoline-wifi,a8:3f:a1:e0:66:ba,-89,Egged.co.il,00:0c:42:51:cf:cd,-81,1.7055488]")
	if r := m.Records[0]; len(r.Network.Cells) != 1 || len(r.Network.WiFi) != 3 || *r.Fix.Sats != 18 {
		t.Fatalf("%+v", r)
	}
	// A WiFi name with brackets stays inside the frame.
	m = decode(t, c, "[3G*8809008845*0047*UD,120623,140020,A,48.949273,N, 4.3783060,E,18.56,43.8,0.0,12,100,76,226120,0,00000000,0,1,[LG_Wall-Mount A/C]e725,66:a1:ed:e1:e7:25,-82,15.0]")
	if nw := m.Records[0].Network; nw == nil || len(nw.WiFi) != 1 {
		t.Fatalf("%+v", nw)
	}
}

// Alarms come from the status word's high half; an AL frame without one
// is a general alarm.
func TestAlarms(t *testing.T) {
	c := newCodec(t, "")
	pos := ",220414,134652,A,22.571707,N,113.8613968,E,0.1,0.0,100,7,60,90,1000,50,%s,0]"
	for status, want := range map[string]string{
		"00010000": "emergency", "00020000": "low-battery", "00040000": "geofence-exit", "00080000": "geofence-enter",
		"00100000": "tamper", "0001": "low-battery", "00000000": "alarm",
	} {
		m := decode(t, c, "[SG*8800000015*0087*AL"+strings.Replace(pos, "%s", status, 1))
		if a := m.Records[0].Alerts; len(a) != 1 || a[0].Type != want {
			t.Errorf("%s: %+v", status, a)
		}
	}
	m := decode(t, c, "[SG*8800000015*0087*UD"+strings.Replace(pos, "%s", "00010000", 1))
	if a := m.Records[0].Alerts; len(a) != 1 || a[0].Type != "emergency" || a[0].Severity != track.Critical {
		t.Fatalf("%+v", a)
	}
}

// Health readings, and command answers naming their command.
func TestHealthAndAnswers(t *testing.T) {
	c := newCodec(t, "")
	m := decode(t, c, "[CS*8800000015*0008*PULSE,72]")
	if m.Records[0].Status["heartRate"] != 72 || m.Correlation != "PULSE" || m.Response == nil {
		t.Fatalf("%+v", m)
	}
	m = decode(t, c, "[ZJ*357653059860416*0007*000c*BLOOD,109,68]")
	if st := m.Records[0].Status; st["bloodPressureHigh"] != 109 || st["bloodPressureLow"] != 68 {
		t.Fatalf("%v", st)
	}
	if st := decode(t, c, "[3G*9705141740*000B*oxygen,0,98]").Records[0].Status; st["bloodOxygen"] != 98 {
		t.Fatalf("%v", st)
	}
	if st := decode(t, c, "[3G*2104326058*000E*btemp2,1,35.29]").Records[0].Status; st["bodyTemperature"] != 35.29 {
		t.Fatalf("%v", st)
	}
	m = decode(t, c, "[SG*5678901234*0005*RESET]")
	if m.Response == nil || *m.Response != "RESET" || m.Correlation != "RESET" || m.Kind != "response" || m.Failed {
		t.Fatalf("%+v", m)
	}
	m = decode(t, c, "[SG*8800000015*0028*VERNO,G29_BASE_V1.00_2014.04.23_17.46.49]")
	if *m.Response != "VERNO,G29_BASE_V1.00_2014.04.23_17.46.49" || m.Correlation != "VERNO" {
		t.Fatalf("%+v", m)
	}
	m = decode(t, c, "[3G*8800000015*0003*TKQ]")
	if string(m.Reply) != "[3G*8800000015*0003*TKQ]" {
		t.Fatalf("%q", m.Reply)
	}
}

// Escaped binary content (voice) is unescaped, framed by brackets and
// passed over with a warning.
func TestBinaryContent(t *testing.T) {
	c := newCodec(t, "")
	bin, _ := hex.DecodeString("7d017d027d037d047d05ff")
	r := bufio.NewReader(strings.NewReader("[CS*1234567890*000e*TK,#!AMR" + string(bin) + "][CS*1234567890*0002*LK]"))
	_, err := c.Decode(r)
	var sk *track.Skip
	if !errors.As(err, &sk) || sk.Code != "mediaNotRead" {
		t.Fatalf("%v", err)
	}
	if m, err := c.Decode(r); err != nil || m.Kind != "link" {
		t.Fatalf("%+v %v", m, err)
	}
	if got := watch.Unescape(bin); hex.EncodeToString(got) != "7d5b5d2c2aff" {
		t.Fatalf("%x", got)
	}
	if got := watch.Escape([]byte("}[],*")); hex.EncodeToString(got) != "7d017d027d037d047d05" {
		t.Fatalf("%x", got)
	}
}

// Commands: the device's vendor (3G answered as SG), ID, index form and
// the hexadecimal length; named commands and the SOS form.
func TestCommands(t *testing.T) {
	c := newCodec(t, "")
	f, answers, err := c.Command("123456789012345", map[string]any{"action": "reboot"}, 1)
	if err != nil || !answers || string(f) != "[CS*123456789012345*0005*RESET]" {
		t.Fatalf("%q %v", f, err)
	}
	f, _, _ = c.Command("123456789012345", map[string]any{"text": "SOS1,123456789"}, 1)
	if string(f) != "[CS*123456789012345*000E*SOS1,123456789]" {
		t.Fatalf("%q", f)
	}
	decode(t, c, "[3G*4700186508*000B*LK,0,10,100]")
	for content, want := range map[string]string{
		`{"action": "locate"}`:                   "[SG*4700186508*0002*CR]",
		`{"action": "interval", "seconds": 300}`: "[SG*4700186508*000A*UPLOAD,300]",
		`{"sos": ["111", "222", "333"]}`:         "[SG*4700186508*000F*SOS,111,222,333]",
		`"POWEROFF"`:                             "[SG*4700186508*0008*POWEROFF]",
	} {
		var v any
		_ = json.Unmarshal([]byte(content), &v)
		f, _, err := c.Command("4700186508", v, 1)
		if err != nil || string(f) != want {
			t.Errorf("%s: %q %v", content, f, err)
		}
	}
	corr, strict := c.(track.Correlator).Correlation(map[string]any{"action": "interval", "seconds": 300}, 1)
	if corr != "UPLOAD" || !strict {
		t.Fatalf("%q %v", corr, strict)
	}
	if _, _, err := c.Command("4700186508", map[string]any{"action": "engineStop"}, 1); !errors.Is(err, track.ErrUnsupported) {
		t.Fatalf("%v", err)
	}
	if _, _, err := c.Command("4700186508", "A]B", 1); err == nil {
		t.Fatal("a bracket in a command accepted")
	}
	// A device with an index field gets one.
	z := newCodec(t, "")
	decode(t, z, "[ZJ*014111001350304*0034*0009*LK,0,0,19]")
	if f, _, _ := z.Command("014111001350304", "CR", 0x2A); string(f) != "[ZJ*014111001350304*002A*0002*CR]" {
		t.Fatalf("%q", f)
	}
	// commandVendor overrides the vendor.
	v := newCodec(t, `{"commandVendor": "3G"}`)
	decode(t, v, "[3G*4700186508*000B*LK,0,10,100]")
	if f, _, _ := v.Command("4700186508", "CR", 1); !strings.HasPrefix(string(f), "[3G*") {
		t.Fatalf("%q", f)
	}
	for _, p := range []string{`{"commandVendor": "X"}`, `{"speedUnit": "furlong"}`, `{"namedCommands": {"x": "y"}}`} {
		if _, err := watch.NewCodec(json.RawMessage(p)); err == nil {
			t.Errorf("%s accepted", p)
		}
	}
}
