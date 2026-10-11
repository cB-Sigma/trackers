package ais140_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/trackers/ais140"
)

// Our own packets in the field layouts of AIS-140 as amended (Amendment 3,
// 04/2026: Table 4A(1) login, Table 4A(2) data with the RFID trailer ID of
// clause 3.1.1.28, Table 3B health, Table 4C i) and ii) emergency;
// Amendment 2, December 2018, clause 8.4: activation and health check
// answers). Every value is made up (IMEIs 86000000000xxxx, ICCIDs
// 8991000..., demo vehicle and tag). The checksums are the XOR of the
// characters between '$' and '*'. Like the standard's own samples, the
// data packet carries alert ID "1" in one digit and the eight-digit
// digital IO of Table 3B.
const (
	samplePVT       = "$PVT,SIGV,02.03.04,NR,1,L,860000000000011,MH12AB3456,1,05032026,083015,18.520430,N,73.856743,E,42.5,215,9,560.0,1.9,0.9,TestNet,1,1,12.7,4.1,0,C,27,404,22,1a2b,3c4d5e6,30,0b1c,2d3e,35,0b1d,4f50,21,0b1e,6172,19,0b1f,8394,0101,01,000417,1.25,0.50,0.310,(),TAG0000DEMO01*53"
	sampleLogin     = "$LGN,MH12AB3456,860000000000029,89910000000000000013,02.03.04,0100,18.520431,N,73.856744,E*59"
	sampleLoginF    = "$LGN,MH12AB3456,860000000000029,8991000000000000021F,02.03.04,0100,18.520431,N,73.856744,E*2E"
	sampleHealth    = "$HLM,SIGV,02.03.04,860000000000029,87,25,12.50,15,60,01000001,1.10,0.40*78"
	sampleEmergency = "$EPB,EMR,860000000000029,NM,21082025174205,A,18.520432,N,73.856745,E,562.0,12.0,0.4,G,MH12AB3456,+910000000001*28"
	sampleSMS       = "$EPB,EMR,860000000000029,18.520433,N,73.856746,E,A,12.0,2b3c,0d4e,21082025174210*49"
	sampleACTVR     = "ACTVR,582901,,V2.0.3,860000000000037,1,18.520434,N,73.856747,E,1,21082025 174300,118.40,33.2,19,404,22,1a2b,1,1,12.9,000512,ID"
	sampleHCHKR     = "HCHKR,730164,,V2.0.3,860000000000037,1,18.520434,N,73.856747,E,1,21082025 174300,118.40,33.2,19,404,22,1a2b,1,1,12.9,000512,ID"
)

// Covers: SIG-IPE-500
func TestAmd3SamplePVT(t *testing.T) {
	m := parse(t, "", samplePVT)
	if m.IMEI != "860000000000011" || m.Kind != ais140.KNormal || len(m.Records) != 1 {
		t.Fatalf("%+v", m)
	}
	r := m.Records[0]
	f := r.Fix
	if f == nil || !f.Valid || f.Lat != 18.52043 || f.Lon != 73.856743 || f.Time.Format(time.RFC3339) != "2026-03-05T08:30:15Z" ||
		*f.Speed != 42.5 || *f.Heading != 215 || *f.Sats != 9 || *f.Alt != 560 || *f.HDOP != 0.9 || r.History {
		t.Fatalf("fix %+v", f)
	}
	want := map[string]any{"vendor": "SIGV", "firmware": "02.03.04", "vehicle": "MH12AB3456", "operator": "TestNet", "ignition": true,
		"mainPower": true, "mainVoltage": 12.7, "batteryVoltage": 4.1, "emergency": false, "boxOpen": false, "gsm": 27,
		"mcc": "404", "mnc": "22", "lac": "1a2b", "cellId": "3c4d5e6", "pdop": 1.9, "digitalInputs": "0101",
		"digitalOutputs": "01", "frame": "000417", "analogInput1": 1.25, "analogInput2": 0.5, "deltaDistance": 0.31}
	for k, v := range want {
		if r.Status[k] != v {
			t.Errorf("status %s = %v (%T), want %v", k, r.Status[k], r.Status[k], v)
		}
	}
	nmr, _ := r.Status["nmr"].([]any)
	// A neighbour's signal above the serving cell's 0 to 31 is kept as sent.
	if len(nmr) != 4 || nmr[0].(map[string]any)["lac"] != "0b1c" || nmr[3].(map[string]any)["cellId"] != "8394" || nmr[1].(map[string]any)["signal"] != 35 {
		t.Errorf("nmr %v", nmr)
	}
	if r.Trailer == nil || *r.Trailer != "TAG0000DEMO01" {
		t.Errorf("trailer %v", r.Trailer)
	}
	if len(r.Alerts) != 0 || m.Response != nil || r.Network != nil {
		t.Errorf("alerts %v response %v network %v", r.Alerts, m.Response, r.Network)
	}
	// Without a GNSS fix the cells become a network report (tracking by
	// cell ID and NMR, Amendment 3 7.1 item 7).
	nofix := strings.Replace(samplePVT, ",MH12AB3456,1,", ",MH12AB3456,0,", 1)
	r = parse(t, "", nofix).Records[0]
	if r.Network == nil || len(r.Network.Cells) != 5 || r.Network.Cells[0].CID != 0x3c4d5e6 || r.Network.Cells[0].LAC != 0x1a2b ||
		r.Network.Cells[0].MCC != 404 || r.Network.Cells[0].MNC != 22 || *r.Network.Cells[0].RSSI != -59 {
		t.Fatalf("network %+v", r.Network)
	}
	// Table 4A(2) without the RFID field (52 fields) reads the same.
	plain := strings.Replace(samplePVT, ",(),TAG0000DEMO01*53", ",()*2F", 1)
	if r := parse(t, "", plain).Records[0]; r.Trailer != nil || r.Status["frame"] != "000417" {
		t.Fatalf("without trailer: %+v", r)
	}
	// A vendor layout under the PVT header still reads by anchors.
	odd := "$PVT,SIGV,02.03.04,NR,1,L,860000000000011,MH12AB3456,1,05032026,083015,18.520430,N,73.912345,E,42.5,215*"
	if r := parse(t, "", odd).Records[0]; r.Fix == nil || r.Fix.Lon != 73.912345 {
		t.Fatalf("anchors: %+v", r)
	}
	// profile.layout auto turns the table layout off.
	if r := parse(t, `{"layout":"auto"}`, samplePVT).Records[0]; r.Trailer != nil || r.Fix.Lat != 18.52043 {
		t.Fatalf("auto layout: %+v", r)
	}
}

// Covers: SIG-IPE-500
func TestAmd3SampleLoginHealthEmergency(t *testing.T) {
	for _, pkt := range []string{sampleLogin, sampleLoginF} {
		m := parse(t, "", pkt)
		r := m.Records[0]
		if !m.Login || m.IMEI != "860000000000029" || m.ICCID == "" || r.Status["iccid"] != m.ICCID || r.Status["firmware"] != "02.03.04" ||
			r.Status["protocolVersion"] != "0100" || r.Status["vehicle"] != "MH12AB3456" || r.Status["loginLat"] != 18.520431 || r.Status["loginLon"] != 73.856744 {
			t.Fatalf("%s: %+v %+v", pkt, m, r.Status)
		}
	}
	m := parse(t, "", sampleHealth)
	h := m.Records[0].Status
	for k, v := range map[string]any{"batteryPercent": 87.0, "lowBatteryThreshold": 25.0, "memoryPercent": 12.5, "updateRateIgnitionOn": 15.0,
		"updateRateIgnitionOff": 60.0, "digitalIO": "01000001", "analogInput1": 1.1, "analogInput2": 0.4, "vendor": "SIGV", "firmware": "02.03.04"} {
		if h[k] != v {
			t.Errorf("health %s = %v, want %v", k, h[k], v)
		}
	}
	if m.Kind != ais140.KHealth || m.IMEI != "860000000000029" {
		t.Fatalf("%+v", m)
	}
	m = parse(t, "", sampleEmergency)
	r := m.Records[0]
	if m.Kind != ais140.KEmergency || r.Fix.Time.Format(time.RFC3339) != "2025-08-21T17:42:05Z" || !r.Fix.Valid || *r.Fix.Alt != 562 ||
		r.Status["provider"] != "G" || r.Status["replyNumber"] != "+910000000001" || r.Status["deltaDistance"] != 0.4 ||
		r.Status["vehicle"] != "MH12AB3456" || r.Alerts[0].Type != "emergency" || r.History {
		t.Fatalf("emergency %+v %+v", r.Status, r.Alerts)
	}
}

// Covers: SIG-IPE-501
func TestAmd3EmergencySMSAndCheckReplies(t *testing.T) {
	m := parse(t, "", sampleSMS)
	r := m.Records[0]
	if m.IMEI != "860000000000029" || r.Fix.Time.Format(time.RFC3339) != "2025-08-21T17:42:10Z" || r.Fix.Lon != 73.856746 || !r.Fix.Valid ||
		r.Status["cellId"] != "2b3c" || r.Status["lac"] != "0d4e" || r.Status["emergencyBy"] != "sms" || r.Alerts[0].Type != "emergency" {
		t.Fatalf("emergency SMS %+v %+v %+v", r.Fix, r.Status, r.Alerts)
	}
	// The six-digit year of the table's description (DDMMYY hhmmss).
	r = parse(t, "", strings.Replace(sampleSMS, "21082025174210", "210825174210", 1)).Records[0]
	if r.Fix.Time.Format(time.RFC3339) != "2025-08-21T17:42:10Z" {
		t.Fatalf("short date %v", r.Fix.Time)
	}
	for pkt, kind := range map[string]string{sampleACTVR: "ACTV", sampleHCHKR: "HCHK"} {
		m := parse(t, "", pkt)
		if m.ReplyKind != kind || m.IMEI != "860000000000037" || m.Kind != ais140.KHealth {
			t.Fatalf("%s: %+v", kind, m)
		}
		r := m.Records[0]
		if r.Fix == nil || r.Fix.Lat != 18.520434 || r.Fix.Lon != 73.856747 || r.Fix.Time.Format(time.RFC3339) != "2025-08-21T17:43:00Z" ||
			*r.Fix.Heading != 118.4 || *r.Fix.Speed != 33.2 || r.Status["gsm"] != 19 || r.Status["batteryVoltage"] != 12.9 || r.Status["frame"] != "000512" {
			t.Fatalf("%s: %+v %+v", kind, r.Fix, r.Status)
		}
		if m.Details["vehicleMode"] != "ID" || m.Details["firmware"] != "V2.0.3" {
			t.Fatalf("%s details %v", kind, m.Details)
		}
	}
	if m := parse(t, "", sampleACTVR); m.ReplyCode != "582901" {
		t.Fatal(m.ReplyCode)
	}
}

// Covers: SIG-IPE-502
func TestAmd3PacketTypesAndAlertIDs(t *testing.T) {
	pkt := func(typ, id, status string) string {
		return strings.NewReplacer(",NR,1,L,", ","+typ+","+id+","+status+",").Replace(samplePVT)
	}
	for _, c := range []struct{ typ, id, want string }{
		{"NR", "01", ""}, {"HP", "01", ""}, {"EA", "10", "emergency"}, {"TA", "09", "box-opened"}, {"IN", "07", "ignition-on"},
		{"IF", "08", "ignition-off"}, {"BD", "03", "main-power-removed"}, {"BR", "06", "main-power-restored"},
		{"BL", "04", "low-battery"}, {"BC", "05", "low-battery-restored"}, {"HB", "13", "harsh-braking"},
		{"HA", "14", "harsh-acceleration"}, {"RT", "15", "rash-turning"}, {"DT", "16", "emergency-wire-cut"},
		{"OA", "12", "ota-parameter-change"}, {"BC", "", "low-battery-restored"}, {"DT", "", "emergency-wire-cut"},
		{"EA", "", "emergency"}, {"OA", "", "ota-parameter-change"},
	} {
		r := parse(t, "", pkt(c.typ, c.id, "L")).Records[0]
		got := ""
		if len(r.Alerts) == 1 {
			got = r.Alerts[0].Type
		}
		if got != c.want || len(r.Alerts) > 1 {
			t.Errorf("%s/%s: %v, want %q", c.typ, c.id, r.Alerts, c.want)
		}
	}
	if r := parse(t, "", pkt("NR", "02", "H")).Records[0]; !r.History {
		t.Error("H is history")
	}
	if r := parse(t, "", pkt("NR", "02", "")).Records[0]; !r.History {
		t.Error("alert 02 without a status is history")
	}
}

// Covers: SIG-IPE-503
func TestAmd3Checksum(t *testing.T) {
	// The routine of item 18 over the characters between '$' and '*' (or
	// with the '$'): both verify.
	body := strings.TrimSuffix(strings.TrimPrefix(samplePVT, "$"), "*53")
	var x byte
	for i := 0; i < len(body); i++ {
		x ^= body[i]
	}
	// The routine gives 53 over the characters between '$' and '*' and 77
	// with the '$' for our data packet.
	if got := fmt.Sprintf("%02X %02X", x, x^'$'); got != "53 77" {
		t.Errorf("sample checksums %s, want 53 77", got)
	}
	for _, sum := range []string{fmt.Sprintf("%02X", x), fmt.Sprintf("%02x", x^'$')} {
		if _, err := parseForTest(`{"checksum":"xor"}`, "$"+body, sum); err != nil {
			t.Errorf("%s: %v", sum, err)
		}
	}
	// The checksums printed in the standard's own samples come out of the
	// routine for neither range (F-179), so checksum: ignore is the
	// default: a wrong checksum is accepted by default and refused with
	// checksum: xor.
	for _, pkt := range []string{samplePVT, sampleLogin, sampleEmergency, sampleSMS} {
		i := strings.IndexByte(pkt, '*')
		if _, err := parseForTest(`{"checksum":"xor"}`, pkt[:i], pkt[i+1:]); err != nil {
			t.Errorf("%s: %v", pkt[:12], err)
		}
		var s byte
		for j := 1; j < i; j++ {
			s ^= pkt[j]
		}
		wrong := fmt.Sprintf("%02X", s^0x01)
		if _, err := parseForTest(`{"checksum":"xor"}`, pkt[:i], wrong); err == nil {
			t.Errorf("%s: a wrong checksum verified", pkt[:12])
		}
		if _, err := parseForTest("", pkt[:i], wrong); err != nil {
			t.Errorf("%s: the default refused a wrong checksum: %v", pkt[:12], err)
		}
	}
}

// Covers: SIG-IPE-504, SIG-IPE-506
func TestOTACommandFraming(t *testing.T) {
	codec := func(profile string) func(dc *device, content any) (string, error) {
		return func(dc *device, content any) (string, error) {
			b, _, err := commandForTest(profile, dc, content)
			return string(b), err
		}
	}
	cmd := codec(`{"otaPassword":"9999"}`)
	dev := &device{IMEI: imei, CommandPassword: "1234"}
	framed := func(body string) string {
		var x byte
		for i := 0; i < len(body); i++ {
			x ^= body[i]
		}
		return fmt.Sprintf("$%s*%02X\r\n", body, x)
	}
	for in, want := range map[string]string{
		`{"op":"SET","param":"002","value":"203.0.113.5"}`:                  imei + ",1234,SET,002:203.0.113.5",
		`{"op":"SET","values":{"pvtPort":"5023","pvtIp":"vlt.example.in"}}`: imei + ",1234,SET,002:vlt.example.in,003:5023",
		`{"op":"GET","param":"firmwareVersion"}`:                            imei + ",1234,GET,001",
		`{"op":"GET","params":["001","022","023"]}`:                         imei + ",1234,GET,001,022,023",
		`{"op":"clr","params":["overspeedLimit","apn"]}`:                    imei + ",1234,CLR,009,007",
	} {
		var v any
		_ = json.Unmarshal([]byte(in), &v)
		got, err := cmd(dev, v)
		if err != nil || got != framed(want) {
			t.Errorf("%s: %q %v, want %q", in, got, err, framed(want))
		}
	}
	// The profile password when the device has none.
	if got, _ := cmd(&device{IMEI: imei}, map[string]any{"op": "GET", "param": "019"}); got != framed(imei+",9999,GET,019") {
		t.Errorf("profile password: %q", got)
	}
	if _, err := codec(`{}`)(&device{IMEI: imei}, map[string]any{"op": "GET", "param": "019"}); err == nil || !strings.Contains(err.Error(), "password") {
		t.Errorf("no password: %v", err)
	}
	for in, why := range map[string]string{
		`{"op":"SET","param":"001","value":"2"}`:                      "does not take SET",
		`{"op":"SET","param":"019","value":"2"}`:                      "does not take SET",
		`{"op":"GET","param":"020"}`:                                  "does not take GET",
		`{"op":"CLR","param":"020"}`:                                  "only from the emergency server or the control centre number",
		`{"op":"SET","param":"999","value":"1"}`:                      "not a command ID",
		`{"op":"SET","param":"007"}`:                                  "needs a value",
		`{"op":"SET","param":"007","value":"a,b"}`:                    "must not contain",
		`{"op":"GET","params":["001","002","003","004","005","006"]}`: "only 5",
		`{"op":"GET","params":["001","firmwareVersion"]}`:             "twice",
		`{"op":"DEL","param":"001"}`:                                  "not SET, GET or CLR",
		`{"op":"GET"}`:                                                "names no parameter",
		`{"op":"GET","values":{"001":"x"}}`:                           "takes",
		`{"op":"SET","param":"009","value":"1","bogus":1}`:            "unknown field",
		`{"text":"a\nb"}`:                                             "one line",
		`{"op":"SET","values":{"002":"1","003":"2","004":"3","005":"4","006":"5","007":"6"}}`: "only 5",
	} {
		var v any
		_ = json.Unmarshal([]byte(in), &v)
		if _, err := cmd(dev, v); err == nil || !strings.Contains(err.Error(), why) {
			t.Errorf("%s: %v, want %q", in, err, why)
		}
	}
	// The emergency server may clear the emergency (020) and read the RFID
	// tag (023), not set the PVT address.
	em := codec(`{"otaRole":"E","otaPassword":"1"}`)
	if got, err := em(dev, map[string]any{"op": "CLR", "param": "clearEmergency"}); err != nil || got != framed(imei+",1234,CLR,020") {
		t.Errorf("E clears: %q %v", got, err)
	}
	if _, err := em(dev, map[string]any{"op": "SET", "param": "002", "value": "x"}); err == nil || !strings.Contains(err.Error(), "only from the PVT server") {
		t.Errorf("E sets 002: %v", err)
	}
	// A manufacturer's own ID.
	ex := codec(`{"otaPassword":"1","otaExtraIds":{"030":"SET,GET"}}`)
	if got, err := ex(dev, map[string]any{"op": "SET", "param": "030", "value": "5"}); err != nil || got != framed(imei+",1234,SET,030:5") {
		t.Errorf("extra ID: %q %v", got, err)
	}
	if _, err := ex(dev, map[string]any{"op": "CLR", "param": "030"}); err == nil {
		t.Error("extra ID took CLR")
	}
	for _, bad := range []string{`{"otaRole":"X"}`, `{"otaExtraIds":{"1":"SET"}}`, `{"otaExtraIds":{"001":"SET"}}`, `{"otaExtraIds":{"030":"PUT"}}`,
		`{"commandFormat":"binary"}`, `{"layout":"fixed"}`, `{"otaPassword":"a,b"}`} {
		if _, err := parseForTest(bad, "$LGN,861693034634154", ""); err == nil {
			t.Errorf("profile %s was accepted", bad)
		}
	}
	// The older text form stays available.
	txt := codec(`{"commandFormat":"text"}`)
	if got, err := txt(dev, map[string]any{"op": "SET", "param": "SL", "value": "60"}); err != nil || got != "SET SL:60\r\n" {
		t.Errorf("text form: %q %v", got, err)
	}
	if got, err := codec(`{"commandTemplate":"#{imei}#{cmd}#\r\n"}`)(dev, map[string]any{"op": "GET", "param": "VN"}); err != nil || got != "#"+imei+"#GET VN#\r\n" {
		t.Errorf("a template means the text form: %q %v", got, err)
	}
}

// Covers: SIG-IPE-505
func TestOTAResponseField(t *testing.T) {
	// Our own responses in the syntax of Table 4D (item 17), in the forms
	// the standard's examples take: a value holding a colon, an extra ID
	// before the item, a trailing empty item (F-182).
	for in, want := range map[string]ais140.OTAResponse{
		"(vlt.example.in:17234|SET|001:vlt.example.in:1)": {Source: "vlt.example.in:17234", Op: "SET",
			Items: []ais140.OTAItem{{ID: "001", Value: "vlt.example.in", OK: true}}},
		"(vlt.example.in:17234|GET|001:vlt.example.in:1|002:16001:1)": {Source: "vlt.example.in:17234", Op: "GET",
			Items: []ais140.OTAItem{{ID: "001", Value: "vlt.example.in", OK: true}, {ID: "002", Value: "16001", OK: true}}},
		"(+910000000001|CLR|002:001:vlt.example.in:1|002:16001:1|)": {Source: "+910000000001", Op: "CLR",
			Items: []ais140.OTAItem{{ID: "002", Value: "001:vlt.example.in", OK: true}, {ID: "002", Value: "16001", OK: true}}},
		"(10.0.0.1:5023|SET|009:80:0)": {Source: "10.0.0.1:5023", Op: "SET", Items: []ais140.OTAItem{{ID: "009", Value: "80", OK: false}}},
	} {
		got, ok := ais140.ParseOTAResponse(in)
		if !ok || fmt.Sprint(*got) != fmt.Sprint(want) {
			t.Errorf("%s: %+v %v", in, got, ok)
		}
	}
	for _, in := range []string{"()", "", "(a|SET)", "(a|PUT|001:x:1)", "(a|SET|001:x:2)", "(a|SET|001)", "a|SET|001:x:1"} {
		if _, ok := ais140.ParseOTAResponse(in); ok {
			t.Errorf("%q read as a response", in)
		}
	}
	// In a PVT packet of alert 12 the field is the command's answer.
	pkt := strings.NewReplacer(",NR,1,L,", ",OA,12,L,", ",(),", ",(10.0.0.1:5023|GET|001:01.01.01:1|023:TAG9:1),").Replace(samplePVT)
	m := parse(t, "", pkt)
	if m.Response == nil || m.Failed || m.Details["values"].(map[string]any)["001"] != "01.01.01" || *m.Records[0].Trailer != "TAG9" {
		t.Fatalf("%+v", m)
	}
	// A value with a comma inside the parentheses.
	pkt = strings.NewReplacer(",NR,1,L,", ",OA,12,L,", ",(),", ",(+919800000000|SET|007:apn,x:0),").Replace(samplePVT)
	if m := parse(t, "", pkt); m.Response == nil || !m.Failed || m.Records[0].Status["frame"] != "000417" {
		t.Fatalf("comma: %+v", m)
	}
	// Outside an alert 12 (OA) packet the field answers no command
	// (SIG-CMD-005).
	pkt = strings.Replace(samplePVT, ",(),", ",(10.0.0.1:5023|GET|001:01.01.01:1),", 1)
	if m := parse(t, "", pkt); m.Response != nil {
		t.Fatalf("an NR packet's OTA field read as an answer: %+v", m)
	}
}

// Covers: SIG-IPE-507
func TestDeviceIDFormat(t *testing.T) {
	d, err := ais140.ParseDeviceID("SIGM01A092600012345")
	if err != nil || d.Manufacturer != "SIGM" || d.Model != "01" || d.TestAgency != 'A' || d.Month != 9 || d.Year != 26 || d.Serial != "00012345" {
		t.Fatalf("%+v %v", d, err)
	}
	for _, a := range "ACIVFPGNR" {
		if _, err := ais140.ParseDeviceID("SIGM01" + string(a) + "092600012345"); err != nil {
			t.Errorf("agency %c: %v", a, err)
		}
	}
	for _, bad := range []string{"SIGM01A09260001234", "SIGM01X092600012345", "SIGM01A132600012345", "SIGM01A002600012345",
		"SIG-01A092600012345", "SIGM01A0926000123A5", "SIGM01A092600012345X"} {
		if _, err := ais140.ParseDeviceID(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
