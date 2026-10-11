// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package suntech_test

import (
	"bufio"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/trackers/suntech"
	"github.com/cB-Sigma/trackers/track"
)

// Device packets quoted in Traccar's SuntechProtocolDecoderTest
// (Apache-2.0), used as test vectors. Each frame ends with '\r' on the
// wire; the tests add it.
const (
	sa200STT  = "SA200STT;317652;042;20120718;15:37:12;16d41;-15.618755;-056.083241;000.024;000.00;8;1;41548;12.17;100000;2;1979"
	sa200EMG  = "SA200EMG;317652;042;20120718;15:35:41;16d41;-15.618740;-056.083252;000.034;000.00;8;1;41548;12.17;110000;1"
	sa200ALT  = "SA200ALT;317652;042;20120829;14:25:58;16d41;-15.618770;-056.083242;000.029;000.00;0;0;2404240;0.00;000000;10"
	sa200ALV  = "SA200ALV;317652"
	st300STT  = "ST300STT;007238270;40;313;20190220;12:05:04;c99e48;+04.644623;-074.076922;010.390;202.77;20;1;997100;14.10;100000;2;8384;003634;4.1;1"
	st300ALT  = "ST300ALT;205174410;14;712;20110101;00:00:07;00000;+20.593923;-100.336716;000.000;000.00;0;0;0;16.57;000000;81;000000;4.0;0;0.00;0000;0000;0;0"
	st300EVT  = "ST300EVT;205173382;07;564;20160322;23:23:18;232e19;+19.288278;-099.128750;000.122;000.00;9;1;478391;11.53;000100;2;1;9498;079324;4.3;1;0.00;0.00;0.00;00000000000000;0;2898E16006000058:-20.8;2861626006000039:+2.5;:"
	st300UEX  = "ST300UEX;100850000;01;010;20081017;07:41:56;2F100;+37.478519;+126.886819;000.012;000.00;9;1;0;15.30;001100;25;Welcome to Suntech World!;12;0;4.5;1"
	st300UEX2 = "ST300UEX;511248287;45;311;20220701;18:42:08;14c943;-22.975257;-043.373065;000.000;000.00;0;0;0;12.14;100010;19;RFID:008FB2BEBA39\r\n;3E;000135;4.1;1;00000000000000;0"
	st300Res  = "ST300CMD;Res;511848119;319H;Disable1"
	st600STT  = "ST600STT;008084783;20;419;20180308;18:00:36;0032cc3e;736;3;445c;41;-16.530023;-068.084267;018.640;267.99;10;1;11655;13.33;100000;2;0336;000061;4.5;0;0.00"
	st600UEX  = "ST600UEX;008728327;20;568;20200602;17:10:03;0bf1a893;334;20;2f19;23;+20.514492;-100.743221;000.033;000.00;12;1;41564973;13.17;000000;44;t_0=1C;N_0=0419.0;t_1=22;N_1=0001.0;Q_D=09\n\r;76;113771;4.1;1"
	st500STT  = "ST500STT;205450135;07;843;20170816;23:24:45;+19.338432;-099.179817;000.283;000.00;6;1;141121;12.89;0;0;1;4659;002.795;0;001.891;611;4.0"
	uniSTT    = "STT;0560001616;BFFFFF;56;1.0.15;1;20200219;20:52:25;00008D6C;334;20;0925;24;+20.741764;-103.430364;0.00;0.00;19;1;00000001;00000000;2;1;1765;00008003;0.0;12.14;136598"
	uniALT    = "ALT;0950030205;3FFFFF;95;1.0.11;0;20221017;21:41:30;02F2F402;334;20;0F1D;45;+25.791061;-100.170745;0.00;0.00;18;1;00000101;00000000;42;2;"
	uniALT2   = "ALT;0950030205;3FFFFF;95;1.0.11;0;20251001;19:34:41;02F2F402;334;20;5B11;28;+25.791061;-100.170745;0.00;0.00;17;1;00000000;00000000;134;1;1440,360,360,360;+23.0;0002;AABBCCDDEEFF"
	uniUEX    = "UEX;1610020241;03FFFFFF;161;3.0.9;0;20240506;15:52:55;00006697;724;11;4EDA;33;-5.129240;-42.797868;0.00;0.00;11;1;00000001;00000000;24;GTSL|6|1|0|22574684|1|\r\n;A7;;164;0;11.82"
	uniRES    = "RES;4309999001;04;02;TEST"
	st410STT  = "ST410STT;007638094;426;01;24153;724;4;-65;365;0;24161;724;4;365;0;0;24162;724;4;365;0;0;24363;724;4;365;0;0;24151;724;4;365;0;0;24991;724;4;365;0;0;24373;724;4;365;0;0;3.98;1;0176;2;016;20200106;19:18:04;-15.571860;-056.062637;000.852;238.28;6;1;201"
	// Universal binary STT (0x81) and ALT (0x82) reports.
	binSTT = "81004e05200013383fffff3401000300130b020b2a0500000000000000000000000047f9ec846a06500000000012010200000123a1002904ba00010fb40000000000000000000000000000000000005989"
	binALT = "82004d05800000553fffff360100100114020410293902ccccf102dc007b00053c00476fa18469e87f000000000b0100003b00081d00000113f3f8010000049e00000000000000001d00000113f3f801"
	// The compressed ("zip") form, passed over.
	binZip = "02003210511340877028813f180c170016041051290c0635652d793653000038001a30e601665e560000000100750002712704000103"
)

// decodeAll reads every frame of the stream; a skipped frame is a nil
// message with its error.
func decodeAll(t *testing.T, profile string, stream []byte) ([]*track.Message, []error) {
	t.Helper()
	nc, err := suntech.NewCodec([]byte(profile))
	if err != nil {
		t.Fatal(err)
	}
	c := nc()
	br := bufio.NewReader(strings.NewReader(string(stream)))
	var ms []*track.Message
	var errs []error
	for {
		m, err := c.Decode(br)
		if errors.Is(err, track.ErrSkip) {
			ms = append(ms, nil)
			errs = append(errs, err)
			continue
		}
		if err != nil {
			return ms, errs
		}
		ms = append(ms, m)
	}
}

func one(t *testing.T, frame string) *track.Message {
	t.Helper()
	ms, errs := decodeAll(t, "", []byte(frame+"\r"))
	if len(ms) != 1 || ms[0] == nil {
		t.Fatalf("%q: decoded %v %v", frame, ms, errs)
	}
	return ms[0]
}

func near(a, b float64) bool { return a-b < 1e-5 && b-a < 1e-5 }

func TestLegacyReports(t *testing.T) {
	for _, tc := range []struct {
		frame       string
		id          string
		at          string
		lat, lon    float64
		valid       bool
		speed, head float64
		sats        int
		alert       string
		history     bool
		status      map[string]any
	}{
		{sa200STT, "317652", "2012-07-18T15:37:12Z", -15.618755, -56.083241, true, 0.024, 0, 8, "", false,
			map[string]any{"firmware": "042", "odometer": 41.548, "externalVoltage": 12.17, "ignition": true, "din1": false, "dout1": false, "mode": 2, "msgNum": 1979, "cellId": "16d41"}},
		{sa200EMG, "317652", "2012-07-18T15:35:41Z", -15.618740, -56.083252, true, 0.034, 0, 8, "emergency/critical", false,
			map[string]any{"emergencyId": 1, "din1": true}},
		{sa200ALT, "317652", "2012-08-29T14:25:58Z", -15.618770, -56.083242, false, 0.029, 0, 0, "", false,
			map[string]any{"alertId": 10}},
		{st300STT, "007238270", "2019-02-20T12:05:04Z", 4.644623, -74.076922, true, 10.39, 202.77, 20, "", false,
			map[string]any{"model": "40", "firmware": "313", "hourMeterMinutes": 3634, "batteryVoltage": 4.1}},
		{st300ALT, "205174410", "2011-01-01T00:00:07Z", 20.593923, -100.336716, false, 0, 0, 0, "", true,
			map[string]any{"alertId": 81, "externalVoltage": 16.57, "batteryVoltage": 4.0}},
		{st300EVT, "205173382", "2016-03-22T23:23:18Z", 19.288278, -99.128750, true, 0.122, 0, 9, "", false,
			map[string]any{"event": 2, "din3": true, "dout1": false}},
		{st600STT, "008084783", "2018-03-08T18:00:36Z", -16.530023, -68.084267, true, 18.64, 267.99, 10, "", true,
			map[string]any{"gsm": 41, "hourMeterMinutes": 61}},
		{st500STT, "205450135", "2017-08-16T23:24:45Z", 19.338432, -99.179817, true, 0.283, 0, 6, "", false,
			map[string]any{"model": "07", "externalVoltage": 12.89}},
	} {
		m := one(t, tc.frame)
		if m.IMEI != tc.id || !m.Login || len(m.Records) != 1 {
			t.Fatalf("%s: %q login %v records %d", tc.frame[:8], m.IMEI, m.Login, len(m.Records))
		}
		r := m.Records[0]
		f := r.Fix
		at, _ := time.Parse(time.RFC3339, tc.at)
		if f == nil || !f.Time.Equal(at) || !near(f.Lat, tc.lat) || !near(f.Lon, tc.lon) || f.Valid != tc.valid ||
			f.Speed == nil || !near(*f.Speed, tc.speed) || f.Heading == nil || !near(*f.Heading, tc.head) || f.Sats == nil || *f.Sats != tc.sats {
			t.Errorf("%s: fix %+v", tc.frame[:8], f)
		}
		var alerts []string
		for _, a := range r.Alerts {
			alerts = append(alerts, a.Type+"/"+a.Severity)
		}
		if strings.Join(alerts, ",") != tc.alert {
			t.Errorf("%s: alerts %v", tc.frame[:8], alerts)
		}
		if r.History != tc.history {
			t.Errorf("%s: history %v", tc.frame[:8], r.History)
		}
		for k, v := range tc.status {
			if r.Status[k] != v {
				t.Errorf("%s: status %s = %#v, want %#v (%v)", tc.frame[:8], k, r.Status[k], v, r.Status)
			}
		}
	}
	if n := one(t, st600STT).Records[0].Network; n == nil || len(n.Cells) != 1 || n.Cells[0] != (track.Cell{MCC: 736, MNC: 3, LAC: 0x445c, CID: 0x0032cc3e}) {
		t.Errorf("ST600 cell %+v", n)
	}
}

// Serial data (UEX) carries its own length; '\r' inside it does not end
// the frame.
func TestSerialData(t *testing.T) {
	for _, tc := range []struct{ frame, data, driver string }{
		{st300UEX, "Welcome to Suntech World!", ""},
		{st300UEX2, "RFID:008FB2BEBA39\r\n", ""},
		{st600UEX, "t_0=1C;N_0=0419.0;t_1=22;N_1=0001.0;Q_D=09\n\r", ""},
		{uniUEX, "GTSL|6|1|0|22574684|1|\r\n", "22574684"},
	} {
		// Two frames back to back: the first must end where its data says.
		ms, errs := decodeAll(t, "", []byte(tc.frame+"\r"+sa200ALV+"\r"))
		if len(ms) != 2 || ms[0] == nil || ms[1] == nil {
			t.Fatalf("%s: %v %v", tc.frame[:8], ms, errs)
		}
		st := ms[0].Records[0].Status
		if st["serialData"] != tc.data {
			t.Errorf("%s: serial data %q", tc.frame[:8], st["serialData"])
		}
		if tc.driver != "" && st["driverId"] != tc.driver {
			t.Errorf("%s: driver %v", tc.frame[:8], st["driverId"])
		}
		if ms[0].Records[0].Fix == nil || ms[1].Kind != "heartbeat" {
			t.Errorf("%s: %+v / %+v", tc.frame[:8], ms[0].Records[0], ms[1])
		}
	}
}

func TestUniversalReports(t *testing.T) {
	m := one(t, uniSTT)
	r := m.Records[0]
	if m.IMEI != "0560001616" || r.Fix == nil || !r.Fix.Valid || !near(r.Fix.Lat, 20.741764) || !near(r.Fix.Lon, -103.430364) ||
		*r.Fix.Sats != 19 || !r.Fix.Time.Equal(time.Date(2020, 2, 19, 20, 52, 25, 0, time.UTC)) || r.History {
		t.Fatalf("STT %q %+v", m.IMEI, r.Fix)
	}
	for k, v := range map[string]any{"model": "56", "firmware": "1.0.15", "ignition": true, "din1": false, "dout1": false,
		"mode": 2, "reportType": 1, "msgNum": 1765, "assign1": "0.0", "assign2": "12.14", "assign16": "136598", "gsm": 24} {
		if r.Status[k] != v {
			t.Errorf("STT %s = %#v, want %#v", k, r.Status[k], v)
		}
	}
	if r.Network == nil || r.Network.Cells[0] != (track.Cell{MCC: 334, MNC: 20, LAC: 0x0925, CID: 0x8D6C}) {
		t.Errorf("STT cell %+v", r.Network)
	}
	m = one(t, uniALT)
	r = m.Records[0]
	if len(r.Alerts) != 1 || r.Alerts[0].Type != "emergency" || r.Alerts[0].Code != "ALT:42" || !r.History || m.Kind != "history" {
		t.Errorf("ALT %+v %s", r, m.Kind)
	}
	if r.Status["ignition"] != true || r.Status["din2"] != true || r.Status["alertModifier"] != "2" {
		t.Errorf("ALT status %v", r.Status)
	}
	r = one(t, uniALT2).Records[0]
	if r.Status["alertId"] != 134 || r.Status["alertData"] != "1440,360,360,360" || r.Status["extra1"] != "+23.0" || r.Status["extra3"] != "AABBCCDDEEFF" {
		t.Errorf("ALT2 %v", r.Status)
	}
}

func TestUniversalBinary(t *testing.T) {
	var stream []byte
	for _, h := range []string{binSTT, binALT, binZip} {
		b, _ := hex.DecodeString(h)
		stream = append(stream, b...)
	}
	stream = append(stream, sa200ALV+"\r"...)
	ms, errs := decodeAll(t, "", stream)
	if len(ms) != 4 || ms[0] == nil || ms[1] == nil || ms[2] != nil || ms[3] == nil {
		t.Fatalf("%v %v", ms, errs)
	}
	var sk *track.Skip
	if !errors.As(errs[0], &sk) || sk.Code != "zipFormat" {
		t.Errorf("zip: %v", errs)
	}
	m := ms[0]
	if m.IMEI != "0520001338" || m.Records[0].Status["ignition"] != false || m.Records[0].Status["firmware"] != "1.0.3" {
		t.Errorf("binary STT %q %v", m.IMEI, m.Records[0].Status)
	}
	m = ms[1]
	f := m.Records[0].Fix
	if m.IMEI != "0580000055" || f == nil || !near(f.Lat, 4.681633) || !near(f.Lon, -74.049663) || !f.Valid ||
		!f.Time.Equal(time.Date(2020, 2, 4, 16, 41, 57, 0, time.UTC)) || m.Records[0].Status["driverId"] != "1d00000113f3f801" {
		t.Errorf("binary ALT %q %+v %v", m.IMEI, f, m.Records[0].Status)
	}
	if n := m.Records[0].Network; n == nil || n.Cells[0] != (track.Cell{MCC: 732, MNC: 123, LAC: 5, CID: 0x02ccccf1}) {
		t.Errorf("binary ALT cell %+v", n)
	}
}

func TestAnswersAndHeartbeats(t *testing.T) {
	m := one(t, st300Res)
	if m.IMEI != "511848119" || m.Kind != "response" || m.Response == nil || *m.Response != "319H;Disable1" || m.Correlation != "Disable1" || m.Failed {
		t.Errorf("legacy answer %+v", m)
	}
	m = one(t, uniRES)
	if m.IMEI != "4309999001" || m.Response == nil || *m.Response != "04;02;TEST" || m.Correlation != "04;02" {
		t.Errorf("universal answer %+v", m)
	}
	for _, f := range []string{sa200ALV, "ALV;0560001616"} {
		m := one(t, f)
		if m.Kind != "heartbeat" || m.IMEI == "" || len(m.Records) != 0 || m.Reply != nil {
			t.Errorf("%s: %+v", f, m)
		}
	}
}

// Frames this package does not read are passed over with a warning;
// line ends between frames are ignored.
func TestPassedOver(t *testing.T) {
	ms, errs := decodeAll(t, "", []byte("\n"+st410STT+"\r\n-Error\r"+"BLE;1140000053;114;1.0.1;20211001;17:27:09;+28.433465;-82.565891;1;-43;-46;-41;ACB89523EF68;247;0;0\r"+sa200ALV+"\r"))
	if len(ms) != 4 || ms[3] == nil {
		t.Fatalf("%v %v", ms, errs)
	}
	codes := []string{}
	for _, e := range errs {
		var sk *track.Skip
		if errors.As(e, &sk) {
			codes = append(codes, sk.Code)
		}
	}
	if strings.Join(codes, ",") != "unknownModel,unknownMessage,unknownMessage" {
		t.Errorf("warnings %v", codes)
	}
}

func TestProfile(t *testing.T) {
	for _, p := range []string{`{"format": "binary"}`, `{"model": "XX"}`, `{"namedCommands": {"reboot": "{seconds}"}}`, `{"other": 1}`, `{"failureWords": [" "]}`} {
		if _, err := suntech.NewCodec([]byte(p)); err == nil {
			t.Errorf("%s accepted", p)
		}
	}
	for _, p := range []string{``, `{"format": "universal"}`, `{"format": "legacy", "model": "ST300"}`, `{"namedCommands": {"interval": "ST300RPT;{imei};02;{seconds}"}}`} {
		if _, err := suntech.NewCodec([]byte(p)); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
}
