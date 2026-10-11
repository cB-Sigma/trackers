package h02_test

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/trackers/h02"
	"github.com/cB-Sigma/trackers/track"
)

// Frames from the HuaSunTeK "GPS Tracker Communication Protocol" V1.0.5
// (https://www.traccar.org/protocol/5013-h02/GPS+Tracker+Platform+Communication+Protocol-From+Winnie+HuaSunTeK-V1.0.5-2017.pdf),
// with the line breaks and padding spaces of the PDF layout removed.
const (
	dV1      = "*HQ,353505910449999,V1,052825,A,2239.4210,N,11400.8825,E,0.00,348,180814,FFFFFFFF,90,3,460,0,9376,8532,9876,4357,0,0 #"
	dXT      = "*HQ,353505910449999,XT#"
	dVP1     = "*HQ,353505910449999,VP1,A,2239.4210,N,11400.8825,E,0.00,348,180814,FFFFFFFF,90#"
	dVP1LBS  = "*HQ,353505910449999,VP1,V,460,0,9376,8532,99Y9876,4357,99Y0,0,99Y#"
	dALRM    = "*HQ,353505910449999,ALRM,1,052825,0,2239.4210,N,11400.8825,E,0.00,348,180814,FFFFFFFF,1CC,0,25FC,F48,90,25FC-F48-10|25FC-F48-6|25FC-F48-7#"
	dBC      = "*HQ,353505910449999,BC,052825,138,A,2239.4210,N,11400.8825,E,0.00,348,03182512,FFFFFFFF,1CC,0,25FC,F48;A,2239.4210,N,11400.8825,E,0.00,348, 03182612,FFFFFFFF,1CC,0,25FC,F48#"
	dS20Fail = "*HQ,2020916012,V4,S20,00,130305,050316,A,2212.8745,N,11346.6574,E,14.28,028, 220902,FFFFFBFF, 460,000,27A6,0F70#"
	dS20OK   = "*HQ,2020916012,V4,S20,80,130305,050316,A,2212.8745,N,11346.6574,E,14.28,028,220902,F7FFFBFF, 460,000,27A6,0F70#"
	dMPFail  = "*HQ,135790246811221,V4,MP,03,130305,050316,A,2212.8745,N,11346.6574,E,14.28,028,220902,FFFFFFFF,mcc,mnc,lac,cid #"
	dCQ      = "*HQ,135790246811221,V4,CQ #"
)

// Frames from the Cantrack "CANTRACK PROTOCOL" A/1
// (https://www.traccar.org/protocol/5013-h02/h02_cantrack_secumore.pdf).
const (
	cV1    = "*HQ,865205030330012,V1,145452,A,2240.55181,N,11358.32389,E,0.00,0,100815,FFFFFBFF#"
	cHTBT  = "*HQ,865205030330012,HTBT#"
	cXT    = "*HQ,865205030330012,XT,V,0,0#"
	cS20   = "*HQ,865205030330012,V4,S20,DONE,130305,050316,A,2212.8745,N,11346.6574,E,14.28,028,220902,F7FFFBFF#"
	cS21   = "*HQ,865205030330012,V4,S21,ERROR,130305,050316,A,2212.87450,N,11346.65740,E,14.28,028,220902,FFFFFBFF#"
	cS1    = "*HQ,865205030330012,V4,S1,130305,050316,A,2212.87450,N,11346.65740,E,14.28,028,220902,FFFFFBFF#"
	cV3    = "*HQ,865205030330012,V3,000201,46000,07,009350,004022,132,-88,009350,004032,140,,009350,004031,139,,009350,004023,133,,009350,004033,127,,009350,004021,124,,010351,003942,118,,0256,0,X,010915,FFFFFBFF#"
	cWKMDv = "*HQ,865205030330012,V4,,,235959,110346,A,2241.07727,N,11400.76820,E,0.00,0,150517,FFFFFBFF#"
)

// Binary records as quoted in open test suites (Traccar's, Apache-2.0: see
// NOTICE); the first mirrors the V1.0.5 document's answer example, the
// second the text frame "*HQ,2705171109,V1,213324,A,5002.5849,N,01433.7822,E,…".
const (
	bDoc  = "2410307310010503162209022212874500113466574C014028fffffbffff0000"
	bText = "2427051711092133391406135002584900014337822e000000ffffffffff0000"
	b45   = "24410600082621532131081504419390060740418306000000fffffbfdff0015060000002c02dc0c000000001f"
)

func hx(s string) string {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}

// decode runs one codec over frames; a skipped frame is a nil message.
func decode(t *testing.T, profile string, frames ...string) ([]*track.Message, []error) {
	t.Helper()
	nc, err := h02.NewCodec(json.RawMessage(profile))
	if err != nil {
		t.Fatal(err)
	}
	c := nc()
	br := bufio.NewReader(strings.NewReader(strings.Join(frames, "")))
	var out []*track.Message
	var skips []error
	for {
		m, err := c.Decode(br)
		if errors.Is(err, track.ErrSkip) {
			out = append(out, nil)
			skips = append(skips, err)
			continue
		}
		if err != nil {
			return out, skips
		}
		out = append(out, m)
	}
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-5 }

func alertTypes(r track.Record) []string {
	var out []string
	for _, a := range r.Alerts {
		out = append(out, a.Type+"/"+a.Code)
	}
	return out
}

// The documents' text frames: positions (time in UTC, knots to km/h,
// ddmm.mmmm to degrees), heartbeats, the cell forms, alarms, the stored
// positions of BC (history) and command answers with their result.
//
// Covers: SIG-IMP-038
func TestDocumentTextFrames(t *testing.T) {
	ms, skips := decode(t, "", dV1, "\r\n", dXT, dVP1, dVP1LBS, dALRM, dBC)
	if len(ms) != 6 || len(skips) != 0 {
		t.Fatalf("decoded %d, skipped %v", len(ms), skips)
	}
	v1 := ms[0]
	if v1.IMEI != "353505910449999" || !v1.Login || v1.Reply != nil {
		t.Fatalf("V1 %+v", v1)
	}
	f := v1.Records[0].Fix
	if f.Time != time.Date(2014, 8, 18, 5, 28, 25, 0, time.UTC) || !f.Valid || !near(f.Lat, 22.6570167) || !near(f.Lon, 114.0147083) || *f.Speed != 0 || *f.Heading != 348 {
		t.Fatalf("V1 fix %+v", f)
	}
	if st := v1.Records[0].Status; st["ignition"] != true || st["fuelCut"] != false || st["statusWord"] != "FFFFFFFF" || len(v1.Records[0].Alerts) != 0 {
		t.Fatalf("V1 status %v %v", st, v1.Records[0].Alerts)
	}
	if ms[1].IMEI != "353505910449999" || ms[1].Login || len(ms[1].Records) != 0 || ms[1].Reply != nil {
		t.Fatalf("XT %+v", ms[1])
	}
	if f := ms[2].Records[0].Fix; !f.Valid || !near(f.Lat, 22.6570167) || time.Since(f.Time) > time.Minute {
		t.Fatalf("VP1 %+v", f)
	}
	if n := ms[3].Records[0].Network; n == nil || len(n.Cells) != 2 || n.Cells[0] != (track.Cell{MCC: 460, MNC: 0, LAC: 9376, CID: 8532}) || n.Cells[1].LAC != 9876 {
		t.Fatalf("VP1 cells %+v", n)
	}
	al := ms[4].Records[0]
	if got := alertTypes(al); len(got) != 1 || got[0] != "emergency/ALRM1" || al.Fix == nil || !al.Fix.Valid || al.Alerts[0].Severity != track.Critical {
		t.Fatalf("ALRM %v %+v", got, al.Fix)
	}
	bc := ms[5].Records
	if len(bc) != 2 || !bc[0].History || !bc[1].History {
		t.Fatalf("BC %+v", bc)
	}
	if t0, t1 := bc[0].Fix.Time, bc[1].Fix.Time; t0.Day() != 3 || t0.Hour() != 18 || t0.Minute() != 25 || t0.Second() != 12 || t1.Sub(t0) != time.Minute || t0.After(time.Now()) {
		t.Fatalf("BC times %v %v", t0, t1)
	}

	// Answers: the result byte (00 failed, 80 done, 03 refused) and the
	// command's echoed time name the command; the answer's position is read.
	ms, _ = decode(t, "", dS20Fail, dS20OK, dMPFail, dCQ)
	if !ms[0].Failed || ms[0].Correlation != "S20,130305" || ms[0].Details["reason"] == nil || ms[0].Records[0].Fix.Time != time.Date(2002, 9, 22, 5, 3, 16, 0, time.UTC) {
		t.Fatalf("S20 00: %+v", ms[0])
	}
	if ms[1].Failed || ms[1].Correlation != "S20,130305" || ms[1].Records[0].Status["fuelCut"] != true || *ms[1].Response != strings.Trim(dS20OK, "*#") {
		t.Fatalf("S20 80: %+v %v", ms[1], ms[1].Records)
	}
	if !ms[2].Failed || ms[2].Correlation != "MP,130305" {
		t.Fatalf("MP 03: %+v", ms[2])
	}
	if ms[3].Failed || ms[3].Correlation != "CQ" || ms[3].Response == nil {
		t.Fatalf("CQ: %+v", ms[3])
	}
}

// The Cantrack document's frames: its V1 (ACC off), the heartbeat forms
// (HTBT echoed back), DONE / ERROR results, V3 cells and the answer without
// a command word.
//
// Covers: SIG-IMP-038
func TestCantrackFrames(t *testing.T) {
	ms, skips := decode(t, "", cV1, cHTBT, cXT, cS20, cS21, cS1, cV3, cWKMDv)
	if len(ms) != 8 || len(skips) != 0 {
		t.Fatalf("decoded %d, skipped %v", len(ms), skips)
	}
	if f := ms[0].Records[0].Fix; !near(f.Lat, 22.6758635) || !near(f.Lon, 113.9720648) || f.Time != time.Date(2015, 8, 10, 14, 54, 52, 0, time.UTC) || ms[0].Records[0].Status["ignition"] != false {
		t.Fatalf("V1 %+v %v", f, ms[0].Records[0].Status)
	}
	if string(ms[1].Reply) != cHTBT {
		t.Fatalf("HTBT reply %q", ms[1].Reply)
	}
	if ms[2].Kind != "health" || ms[2].Reply != nil {
		t.Fatalf("XT %+v", ms[2])
	}
	if ms[3].Failed || ms[3].Correlation != "S20,130305" || ms[3].Details["result"] != "DONE" {
		t.Fatalf("S20 DONE %+v", ms[3])
	}
	if !ms[4].Failed || ms[4].Correlation != "S21,130305" {
		t.Fatalf("S21 ERROR %+v", ms[4])
	}
	if ms[5].Failed || ms[5].Correlation != "S1,130305" || ms[5].Records[0].Fix == nil {
		t.Fatalf("S1 %+v", ms[5])
	}
	r := ms[6].Records[0]
	if n := r.Network; len(n.Cells) != 7 || n.Cells[0].MCC != 460 || n.Cells[0].MNC != 0 || n.Cells[0].LAC != 9350 || n.Cells[0].CID != 4022 || *n.Cells[0].RSSI != -88 || n.Cells[1].RSSI != nil {
		t.Fatalf("V3 %+v", r.Network)
	}
	if r.Status["batteryVoltage"] != 3.27 || r.Time != time.Date(2015, 9, 1, 0, 2, 1, 0, time.UTC) {
		t.Fatalf("V3 status %v %v", r.Status, r.Time)
	}
	if ms[7].Response == nil || ms[7].Correlation != "" || ms[7].Records[0].Fix == nil {
		t.Fatalf("V4 without a command %+v", ms[7])
	}
}

// Binary '$' records: packed BCD id, time, date, coordinates, the
// validity and hemisphere nibble, knots and course, and the status word;
// the 45-byte form is read too, and text frames follow on the same stream.
//
// Covers: SIG-IMP-038
func TestBinaryRecords(t *testing.T) {
	ms, skips := decode(t, "", hx(bDoc), hx(bText), hx(b45), cHTBT)
	if len(ms) != 4 || len(skips) != 0 {
		t.Fatalf("decoded %d, skipped %v", len(ms), skips)
	}
	f := ms[0].Records[0].Fix
	if ms[0].IMEI != "1030731001" || f.Time != time.Date(2002, 9, 22, 5, 3, 16, 0, time.UTC) || !near(f.Lat, 22.214575) || !near(f.Lon, 113.7776233) || f.Valid || *f.Speed != 25.93 || *f.Heading != 28 {
		t.Fatalf("doc record %s %+v", ms[0].IMEI, f)
	}
	f = ms[1].Records[0].Fix
	if ms[1].IMEI != "2705171109" || f.Time != time.Date(2013, 6, 14, 21, 33, 39, 0, time.UTC) || !near(f.Lat, 50.0430817) || !near(f.Lon, 14.5630367) || !f.Valid {
		t.Fatalf("text-twin record %+v", f)
	}
	if ms[2].IMEI != "4106000826" || ms[2].Records[0].Fix == nil || ms[3].IMEI != "865205030330012" {
		t.Fatalf("45-byte record then text: %+v %+v", ms[2], ms[3])
	}
	// The simulator's records read back the same.
	now := time.Now().UTC().Truncate(time.Second)
	ms, _ = decode(t, "", string(binaryFrame("2020916012", binPos{Time: now, Lat: -12.5, Lon: -77.25, Speed: 10, Course: 271, Valid: true})))
	if f := ms[0].Records[0].Fix; f.Time != now || !near(f.Lat, -12.5) || !near(f.Lon, -77.25) || *f.Heading != 271 || *f.Speed != 18.52 {
		t.Fatalf("sim record %+v", f)
	}
}

// Status-word alarms are raised when they become active, not on every
// report; ignition changes and power restoring are events too.
//
// Covers: SIG-IMP-038
func TestStatusWordAlerts(t *testing.T) {
	v1 := func(w string) string {
		return "*HQ,353588020068342,V1,084436,A,3257.01525,N,00655.03865,W,57.78,40,011216," + w + ",25c,a, 154,b04c#"
	}
	ms, _ := decode(t, "", v1("FFFBFBFF"), v1("FFFBFBFF"), v1("FFF7FFFF"), v1("FFFFFFFF"), v1("FFFFEFFF"))
	want := [][]string{
		{"emergency/bit18"},
		nil,
		{"main-power-removed/bit19", "ignition-on/bit10"},
		{"main-power-restored/"},
		{"low-battery/bit12"},
	}
	for i, m := range ms {
		got := alertTypes(m.Records[0])
		if strings.Join(got, " ") != strings.Join(want[i], " ") {
			t.Errorf("frame %d: alerts %v, want %v", i, got, want[i])
		}
	}
	if f := ms[0].Records[0].Fix; *f.Speed != 107.01 || f.Lon > 0 {
		t.Fatalf("fix %+v", f)
	}
}

// Unknown message types and frames that are not H02 are passed over with a
// warning, and the frames after them are read.
//
// Covers: SIG-IMP-038, SIG-IMP-041
func TestUnknownFramesSkipped(t *testing.T) {
	ms, skips := decode(t, "", "garbage\r\n", "*HQ,353505910449999,ZZ9,1,2#", "*not h02#", cV1)
	if len(ms) != 3 || ms[0] != nil || ms[1] != nil || ms[2] == nil {
		t.Fatalf("messages %v", ms)
	}
	var sk *track.Skip
	if !errors.As(skips[0], &sk) || sk.Code != "unknownMessage" || !strings.Contains(sk.Detail, "ZZ9") {
		t.Fatalf("skip %v", skips[0])
	}
	if !errors.As(skips[1], &sk) || sk.Code != "unknownPacket" {
		t.Fatalf("skip %v", skips[1])
	}
}
