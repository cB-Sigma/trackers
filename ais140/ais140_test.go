package ais140_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/trackers/ais140"
	"github.com/cB-Sigma/trackers/track"
)

func parse(t *testing.T, profile, pkt string) *track.Message {
	t.Helper()
	text, sum := pkt, ""
	if i := strings.IndexByte(pkt, '*'); i >= 0 {
		text, sum = pkt[:i], pkt[i+1:]
	}
	m, err := parseForTest(profile, text, sum)
	if err != nil {
		t.Fatalf("%s: %v", pkt, err)
	}
	return m.(*track.Message)
}

// Packets from AIS-140 devices of several manufacturers, as published in an
// open-source tracking server's test suite (Traccar, Apache-2.0; data, not
// prose; attribution in the repository's NOTICE file).
var fieldVectors = []struct {
	pkt            string
	login, history bool
	imei           string
	lat, lon       float64
	when           string // RFC 3339, "" for none
	alert          string
	status         map[string]any
}{
	{pkt: "$,LGN,MARK,000000000,358980100077446,V0.0.1,AIS140,19.804487,N,75.225876,E,*", login: true, imei: "358980100077446"},
	{pkt: "$LGN,,869867037009679,3.2AIH,9.99546000,N,76.35886167,E", login: true, imei: "869867037009679"},
	{pkt: "$Header,nliven,KA01I2000,861693034634154,1_37T02B0164MAIS,AIS140,12.976545,N,77.549759,E*50", login: true, imei: "861693034634154", status: map[string]any{"vehicle": "KA01I2000"}},
	{pkt: "$,NRM,MARK,V0.0.1,NR,01,L,358980100040246,000000000,1,10032021,073239,25.932051,N,71.509872,E,0.6,1.40,13,211.2,1.4,0.7,IDEA,0,1,0.1,3.7,0,N,20,404,60,A5F,FD3F,A5F,6F88,29,A5F,5855,18,A5F,6F87,18,A5F,FD41,14,0000,00,0.1,0,000027,0,0,0,4E9C,*",
		imei: "358980100040246", lat: 25.932051, lon: 71.509872, when: "2021-03-10T07:32:39Z", status: map[string]any{"ignition": false, "mainPower": true, "batteryVoltage": 3.7, "gsm": 20, "mcc": "404"}},
	{pkt: "$NRM,ROADRPA,3.5AIS,NR,01,L,869867036940288,,1,04012020,094901,23.18731933,N,77.45079633,E,0.0,0.00,13,545.6,1.10,0.60,Idea Cellular Ltd,0,1,13.2,4.1,0,C,31,404,78,62E1,5799,29,62E1,579B,23,62E1,52EB,22,62E1,52EA,21,62E1,2FF1,0100,00,0,0,001926,8252.226,-,-,-,-,5_5_5_5_0,171B56E1*",
		imei: "869867036940288", lat: 23.18731933, lon: 77.45079633, when: "2020-01-04T09:49:01Z", status: map[string]any{"boxOpen": false, "mainVoltage": 13.2, "gsm": 31, "operator": "Idea Cellular Ltd"}},
	{pkt: "$NMP,GPSBOX,1.6.8,NR,H,868997035844834,0000,1,220519,035419,28.6291409,N,77.3928299,E,015.2,157.40,07,197.86,2.1,1.0,airtel,1,1,13.3,4.1,0,O,31,404,10,0099,79b4,(-57,0099,334c,x,x,x,x,x,x,x,x,x),0012,00,000348,2,08.4,00.3,(0,0,0),CD*",
		history: true, imei: "868997035844834", lat: 28.6291409, lon: 77.3928299, when: "2019-05-22T03:54:19Z"},
	{pkt: "$Header,iTriangle,1_37T02B0164MAIS,BR,6,L,861693034634154,KA01I2000,1,09112017,160702,12.976593,N,77.549782,E,25.1,344,15,911.0,1.04,0.68,Airtel,1,1,11.8,3.8,1,C,24,404,45,61b4,9ad9,31,9adb,61b4,35,ffff,0000,33,ffff,0000,31,ffff,0000,0001,00,000014,0.0,0.1,4,()*1E",
		imei: "861693034634154", lat: 12.976593, lon: 77.549782, when: "2017-11-09T16:07:02Z", alert: "main-power-restored", status: map[string]any{"emergency": true, "vehicle": "KA01I2000"}},
	{pkt: "$,03,XYZ123,0.0.1,TA,16,L,869867035297185,MH12AB1234,1,20,02,2019,10,59,13,023.482630,N,086.399673,E,000.1,015.19,21,212.3,01.12,00.58,NOSERV,0,1,00.0,4.6,1,C,11,404,75,082a,db3a,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,0000,01,000013,01dbd51f,",
		imei: "869867035297185", lat: 23.48263, lon: 86.399673, when: "2019-02-20T10:59:13Z", alert: "emergency-wire-cut"},
	{pkt: "$,ID01,SAT,1.0.0,NR,1,L,868345034056903,DL3CAB1021,1,27052019,040234,28.359895,N,76.927879,E,0.0,285.6,12,254.9,1.4,0.7,IDEA,1,1,12.6,3.8,0,25,404,04,0138,0927,4ECD,0138,41,1C2B,0138,37,D77A,0138,34,D843,0138,33,0000,00,0.03,0.00,000091,A3,*",
		imei: "868345034056903", lat: 28.359895, lon: 76.927879, when: "2019-05-27T04:02:34Z", status: map[string]any{"gsm": 25, "ignition": true}},
	{pkt: "$,EPB,EMR,868997031721531,NM,14072020111520,A,28.359959,N,076.927553,E,261.41,0.1,0.0,G,NA00000000,N.A0000000,*",
		imei: "868997031721531", lat: 28.359959, lon: 76.927553, when: "2020-07-14T11:15:20Z", alert: "emergency"},
	{pkt: "$,EPB,SEM,868997031721531,NM,14072020112020,A,28.359959,N,076.927566,E,260.93,0.1,0.0,G,NA00000000,N.A0000000,*",
		imei: "868997031721531", lat: 28.359959, lon: 76.927566, when: "2020-07-14T11:20:20Z", alert: "emergency-off"},
	{pkt: "$EPB,iTriangle1,EMR,864495034445822,SP,03082018110730,A,22.829292,N,75.935806,E,543.0,0.0,0,G,KA01G1234,+9164061023*13",
		history: true, imei: "864495034445822", lat: 22.829292, lon: 75.935806, when: "2018-08-03T11:07:30Z", alert: "emergency"},
	{pkt: "$,02,XYZ123,0.0.1,861359034137271,100,30,00.0,00005,00600,1000,01,00.1,00.0,", imei: "861359034137271",
		status: map[string]any{"batteryPercent": 100.0, "lowBatteryThreshold": 30.0, "updateRateIgnitionOff": 600.0, "digitalIO": "1000"}},
	{pkt: "$,01,XYZ123,0.0.1,861359034137271,MH12AB1234,", login: true, imei: "861359034137271", status: map[string]any{"vehicle": "MH12AB1234"}},
}

// Covers: SIG-IPE-480, SIG-IPE-481
func TestFieldVectors(t *testing.T) {
	for _, v := range fieldVectors {
		m := parse(t, "", v.pkt)
		name := v.pkt[:24]
		if m.IMEI != v.imei || m.Login != v.login {
			t.Errorf("%s: imei %q login %v", name, m.IMEI, m.Login)
			continue
		}
		var r track.Record
		if len(m.Records) > 0 {
			r = m.Records[0]
		}
		if r.History != v.history {
			t.Errorf("%s: history %v", name, r.History)
		}
		if v.lat != 0 {
			if r.Fix == nil || !near(r.Fix.Lat, v.lat) || !near(r.Fix.Lon, v.lon) || !r.Fix.Valid {
				t.Errorf("%s: fix %+v", name, r.Fix)
			} else if got := r.Fix.Time.Format(time.RFC3339); got != v.when {
				t.Errorf("%s: time %s, want %s", name, got, v.when)
			}
		} else if r.Fix != nil {
			t.Errorf("%s: unexpected fix", name)
		}
		switch {
		case v.alert == "" && len(r.Alerts) > 0:
			t.Errorf("%s: unexpected alerts %v", name, r.Alerts)
		case v.alert != "" && (len(r.Alerts) != 1 || r.Alerts[0].Type != v.alert):
			t.Errorf("%s: alerts %v, want %s", name, r.Alerts, v.alert)
		}
		for k, want := range v.status {
			if got := r.Status[k]; got != want {
				t.Errorf("%s: status %s = %v (%T), want %v", name, k, got, got, want)
			}
		}
	}
}

func near(a, b float64) bool { return a-b < 1e-6 && b-a < 1e-6 }

// Covers: SIG-IPE-482
func TestChecksumsAndLayouts(t *testing.T) {
	// CRC-32 as the last field (a manufacturer's variation).
	good := "$NRM,ROADRPA,1.7AIS,NR,01,L,869867036345389,,1,25022019,051716,25.12891000,N,75.85587833,E,7.6,350.00,14,284.8,1.00,1.00,AIRTEL,1,1,28.0,4.2,0,C,13,404,70,4E3B,3C84,11,4E3B,39B8,08,4E3B,3965,07,4E3B,48B5,07,4E3B,3C85,0000,00,000551,71978C6B"
	if m := parse(t, `{"checksum":"crc32"}`, good); len(m.Records) != 1 || m.Records[0].Fix.Speed == nil || *m.Records[0].Fix.Speed != 7.6 {
		t.Fatalf("crc32: %+v", m)
	}
	if _, err := parseForTest(`{"checksum":"crc32"}`, strings.Replace(good, "7.6", "7.7", 1), ""); err == nil {
		t.Fatal("a corrupted packet passed the CRC-32 check")
	}
	// XOR after '*'.
	body := "$LGN,KA01F1234,861693034634154,1.0,AIS140,12.9,N,77.5,E"
	var x byte
	for i := 1; i < len(body); i++ {
		x ^= body[i]
	}
	sum := fmt.Sprintf("%02X", x)
	if _, err := parseForTest(`{"checksum":"xor"}`, body, sum); err != nil {
		t.Fatalf("xor: %v", err)
	}
	if _, err := parseForTest(`{"checksum":"xor"}`, body, "00"); err == nil && x != 0 {
		t.Fatal("a bad XOR checksum passed")
	}
	// An explicit layout for a vendor that puts the IMEI first.
	prof := `{"fields":["header","imei","packetType","alertId","packetStatus","date","time","lat","latDir","lon","lonDir","speed","ignition"]}`
	m := parse(t, prof, "$XYZ,861693034634154,HB,13,L,24092026,101500,12.5,N,77.25,E,48.0,1*")
	r := m.Records[0]
	if m.IMEI != "861693034634154" || r.Fix.Time.Format(time.RFC3339) != "2026-09-24T10:15:00Z" || r.Alerts[0].Type != "harsh-braking" || r.Status["ignition"] != true {
		t.Fatalf("explicit layout: %+v %+v", m, r)
	}
	// A timezone for devices that send local time.
	m = parse(t, `{"timezone":"Asia/Kolkata"}`, "$NRM,V,1,NR,01,L,861693034634154,KA01F1234,1,24092026,153000,12.5,N,77.25,E,0,0,9,900,1,1,X,1,1,12,4,0,C,20,404,45,1,2*")
	if got := m.Records[0].Fix.Time.Format(time.RFC3339); got != "2026-09-24T10:00:00Z" {
		t.Fatalf("timezone: %s", got)
	}
	for _, bad := range []string{`{"checksum":"md5"}`, `{"fields":["imei","nope"]}`, `{"fields":["imei"]}`, `{"alertIds":{"x":"y"}}`, `{"commandTemplate":"x"}`, `{"timezone":"Mars/Base"}`, `{"unknown":1}`} {
		if _, err := parseForTest(bad, "$LGN,861693034634154", ""); err == nil {
			t.Errorf("profile %s was accepted", bad)
		}
	}
	// Custom alert IDs and packet types extend the defaults.
	m = parse(t, `{"alertIds":{"30":"door-open"}}`, "$NRM,V,1,XX,30,L,861693034634154,KA01F1234,1,24092026,153000,12.5,N,77.25,E,0,0,9,900,1,1,X,1,1,12,4,0,C,20*")
	if a := m.Records[0].Alerts; len(a) != 1 || a[0].Type != "door-open" {
		t.Fatalf("custom alert: %v", a)
	}
}

// Covers: SIG-IPE-483
func TestOTACommandText(t *testing.T) {
	for in, want := range map[string]string{
		`{"op":"SET","param":"sl","value":"60"}`: "SET SL:60",
		`{"op":"GET","param":"PIP"}`:             "GET PIP",
		`{"op":"clr","param":"EO"}`:              "CLR EO",
		`{"text":"SET UR:10"}`:                   "SET UR:10",
		`"GET VN"`:                               "GET VN",
	} {
		var v any
		_ = json.Unmarshal([]byte(in), &v)
		got, err := ais140.OTAText(v)
		if err != nil || got != want {
			t.Errorf("%s: %q %v", in, got, err)
		}
	}
	for _, in := range []string{`{"op":"SET","param":"SL"}`, `{"op":"DEL","param":"SL"}`, `{"op":"SET","param":"S L","value":"1"}`, `{"text":"a\nb"}`, `{"cmd":"x"}`} {
		var v any
		_ = json.Unmarshal([]byte(in), &v)
		if _, err := ais140.OTAText(v); err == nil {
			t.Errorf("%s accepted", in)
		}
	}
}

const imei = "861693034634154"
