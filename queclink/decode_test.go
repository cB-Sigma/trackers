package queclink_test

import (
	"bufio"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/trackers/queclink"
	"github.com/cB-Sigma/trackers/track"
)

// Example frames of Queclink's GV300N @Track Air Interface Protocol 3.01
// (TRACGV300NAN001), copied byte for byte, including the document's stray
// spaces (GTIGN, ACK:GTCRA).
const (
	vFRI     = "+RESP:GTFRI,250301,135790246811220,,,00,1,1,4.3,92,70.0,121.354335,31.222073,20090214013254,0460,0000,18d8,6141,00,2000.0,12345:12:34,,,80,210100,,,,20090214093254,11F0$"
	vFRI2    = "+RESP:GTFRI,250301,135790246811220,,,00,2,1,4.3,92,70.0,121.354335,31.222073,20090214013254,0460,0000,18d8,6141,00,0,4.3,92,70.0,121.354335,31.222073,20090101000000,0460,0000,18d8,6141,00,2000.0,12345:12:34,,,80,210100,,,,20090214093254,11F0$"
	vBuff    = "+BUFF:GTFRI,020100,135790246811220,,0,0,1,1,4.3,92,70.0,121.354335,31.222073,20090214013254,0460,0000,18d8,6141,00,,20090214093254,11F0$"
	vSOS     = "+RESP:GTSOS,250301,135790246811220,,,00,1,1,4.3,92,70.0,121.354335,31.222073,20090214013254,0460,0000,18d8,6141,00,2000.0,20090214093254,11F0$"
	vSPD     = "+RESP:GTSPD,250301,135790246811220,,,00,1,1,4.3,92,70.0,121.354335,31.222073,20090214013254,0460,0000,18d8,6141,00,2000.0,20090214093254,11F0$"
	vHBM     = "+RESP:GTHBM,250301,135790246811220,,,11,1,1,24.3,92,70.0,121.354335,31.222073,20090214013254,0460,0000,18d8,6141,00,2000.0,20090214093254,11F0$"
	vIGN     = "+RESP:GTIGN,250301,135790246811220,,1200,0,4.3,92,70.0,121.354335,31.222073,20090214013254,0460,0000,18d8,6141,00, 12345:12:34,2000.0,20090214093254,11F0$"
	vMPF     = "+RESP:GTMPF,250301,135790246811220,,0,4.3,92,70.0,121.354335,31.222073,20090214013254,0460,0000,18d8,6141,00,20090214093254,11F0$"
	vGEO     = "+RESP:GTGEO,250301,135790246811220,,,00,1,1,4.3,92,70.0,121.354335,31.222073,20090214013254,0460,0000,18d8,6141,00,2000.0,20090214093254,11F0$"
	vSTT     = "+RESP:GTSTT,250301,135790246811220,,16,0,4.3,92,70.0,121.354335,31.222073,20090214013254,0460,0000,18d8,6141,00,20090214093254,11F0$"
	vBPL     = "+RESP:GTBPL,250301,135790246811220,,3.53,0,4.3,92,70.0,121.354335,31.222073,20090214013254,0460,0000,18d8,6141,00,20090214093254,11F0$"
	vINF     = "+RESP:GTINF,250301,135790246811220,,16,898600810906F8048812,16,0,1,12000,,4.40,0,0,0,0,20090214013254,0,1300,2000,00,00,+0800,0,20090214093254,11F0$"
	vHBD     = "+ACK:GTHBD,250301,135790246811220,,20100214093254,11F0$"
	vHBDSack = "+SACK:GTHBD,250301,11F0$"
	vAckOUT  = "+ACK:GTOUT,250301,135790246811220,,0004,20090214093254,11F0$"
	vAckRTO  = "+ACK:GTRTO,250301,135790246811220,,IOS,0015,20090214093254,11F1$"
	vAckCRA  = "+ACK:GTCRA, 250202,135790246811220,,0019,20090214093254,11F0$"
	docIMEI  = "135790246811220"
)

// decode reads every frame of text; a skipped frame is a nil message.
func decode(t *testing.T, profile, text string) ([]*track.Message, []error) {
	t.Helper()
	c, err := queclink.NewCodecForTest(profile, 0)
	if err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(strings.NewReader(text))
	var ms []*track.Message
	var skips []error
	for {
		m, err := c.Decode(br)
		if errors.Is(err, track.ErrSkip) {
			ms = append(ms, nil)
			skips = append(skips, err)
			continue
		}
		if err != nil {
			return ms, skips
		}
		ms = append(ms, m)
	}
}

func one(t *testing.T, frame string) *track.Message {
	t.Helper()
	ms, _ := decode(t, "", frame)
	if len(ms) != 1 || ms[0] == nil {
		t.Fatalf("%s: decoded %v", frame, ms)
	}
	if ms[0].IMEI != docIMEI {
		t.Fatalf("%s: imei %q", frame, ms[0].IMEI)
	}
	return ms[0]
}

func alertTypes(r track.Record) []string {
	var out []string
	for _, a := range r.Alerts {
		out = append(out, a.Type+"/"+a.Severity)
	}
	return out
}

// The document's sample reports: positions in degrees, km/h and UTC,
// the odometer, the device status and the alerts each report type means.
//
// Covers: SIG-IMP-020
func TestDocumentFrames(t *testing.T) {
	m := one(t, vFRI)
	if !m.Login || m.Reply != nil || len(m.Records) != 1 {
		t.Fatalf("GTFRI %+v", m)
	}
	r := m.Records[0]
	f := r.Fix
	if f == nil || !f.Valid || f.Lat != 31.222073 || f.Lon != 121.354335 || *f.Speed != 4.3 || *f.Heading != 92 || *f.Alt != 70 || *f.HDOP != 1 {
		t.Fatalf("GTFRI fix %+v", f)
	}
	if f.Time != time.Date(2009, 2, 14, 1, 32, 54, 0, time.UTC) || r.History {
		t.Fatalf("GTFRI time %v history %v", f.Time, r.History)
	}
	st := r.Status
	if st["odometer"] != 2000.0 || st["hourMeter"] != "12345:12:34" || st["batteryLevel"] != 80 || st["ignition"] != true ||
		st["motionState"] != "ignitionOnRest" || st["din1"] != false || st["dout1"] != false {
		t.Fatalf("GTFRI status %v", st)
	}
	if c := r.Network.Cells[0]; c.MCC != 460 || c.MNC != 0 || c.LAC != 0x18d8 || c.CID != 0x6141 {
		t.Fatalf("GTFRI cell %+v", c)
	}

	m = one(t, vFRI2)
	if len(m.Records) != 2 || m.Records[1].Fix.Time != time.Date(2009, 1, 1, 0, 0, 0, 0, time.UTC) || m.Records[1].Fix.Valid ||
		m.Records[1].Status["odometer"] != 2000.0 || m.Records[0].Status != nil {
		t.Fatalf("GTFRI with two positions: %+v", m.Records)
	}

	m = one(t, vBuff)
	if !m.Records[0].History || m.Records[0].Fix == nil || m.Records[0].Fix.Lat != 31.222073 {
		t.Fatalf("+BUFF %+v", m.Records)
	}

	for frame, want := range map[string]string{
		vSOS: "emergency/critical", vSPD: "over-speed/minor", vMPF: "main-power-removed/major",
		vGEO: "geofence-exit/minor", vBPL: "low-battery/minor", vIGN: "ignition-on/info",
	} {
		m := one(t, frame)
		r := m.Records[len(m.Records)-1]
		if got := alertTypes(r); len(got) != 1 || got[0] != want || r.Fix == nil {
			t.Errorf("%s: alerts %v, want %s", frame[:11], got, want)
		}
	}
	if m := one(t, vSOS); m.Kind != "emergency" {
		t.Errorf("GTSOS kind %q", m.Kind)
	}
	if got := alertTypes(one(t, vHBM).Records[0]); len(got) != 1 || got[0] != "harsh-acceleration/minor" {
		t.Errorf("GTHBM type 1: %v", got)
	}
	if st := one(t, vIGN).Records[0].Status; st["ignition"] != true || st["hourMeter"] != "12345:12:34" || st["odometer"] != 2000.0 {
		t.Errorf("GTIGN status %v", st)
	}
	if st := one(t, vMPF).Records[0].Status; st["mainPower"] != false {
		t.Errorf("GTMPF status %v", st)
	}
	if r := one(t, vMPF).Records[0]; r.Fix.Valid || r.Fix.Lat != 31.222073 {
		t.Errorf("GTMPF fix (accuracy 0 is no fix): %+v", r.Fix)
	}
	if st := one(t, vSTT).Records[0].Status; st["motionState"] != "towed" || st["ignition"] != false {
		t.Errorf("GTSTT status %v", st)
	}
	if st := one(t, vBPL).Records[0].Status; st["batteryVoltage"] != 3.53 {
		t.Errorf("GTBPL status %v", st)
	}
	st = one(t, vINF).Records[0].Status
	if st["iccid"] != "898600810906F8048812" || st["gsm"] != 16 || st["mainPower"] != true || st["externalVoltage"] != 12.0 ||
		st["batteryVoltage"] != 4.4 || st["charging"] != false || st["motionState"] != "towed" {
		t.Errorf("GTINF status %v", st)
	}

	// The heartbeat is answered with the document's +SACK:GTHBD.
	if m := one(t, vHBD); string(m.Reply) != vHBDSack || m.Response != nil {
		t.Errorf("heartbeat reply %q", m.Reply)
	}
	// Command acknowledgements carry the command's serial number.
	for frame, corr := range map[string]string{vAckOUT: "GTOUT/0004", vAckRTO: "GTRTO/0015", vAckCRA: "GTCRA/0019"} {
		m := one(t, frame)
		if m.Response == nil || *m.Response != frame || m.Correlation != corr || m.Failed || m.Reply != nil {
			t.Errorf("%s: response %v correlation %q", frame, m.Response, m.Correlation)
		}
	}
	if d := one(t, vAckRTO).Details; d["subCommand"] != "IOS" || d["serial"] != "0015" {
		t.Errorf("GTRTO ack details %v", d)
	}
}

// With profile.sack every report and acknowledgement is answered with
// +SACK:<count>$ (the document's server acknowledgement); without it only
// heartbeats are answered.
//
// Covers: SIG-IMP-020
func TestServerAcknowledgement(t *testing.T) {
	ms, _ := decode(t, `{"sack": true}`, vFRI+vAckOUT+vHBD)
	if len(ms) != 3 || string(ms[0].Reply) != "+SACK:11F0$" || string(ms[1].Reply) != "+SACK:11F0$" || string(ms[2].Reply) != vHBDSack {
		t.Fatalf("sack replies %+v", ms)
	}
	if _, err := queclink.NewCodecForTest(`{"alerts": {"PFA": "tamper"}}`, 0); err == nil {
		t.Fatal("a malformed report name in alerts was accepted")
	}
	ms, _ = decode(t, `{"alerts": {"GTPFA": "tamper"}}`, "+RESP:GTPFA,250301,135790246811220,,20090214093254,11F0$")
	if len(ms) != 1 || ms[0] == nil || alertTypes(ms[0].Records[0])[0] != "tamper/major" || ms[0].Records[0].Status["devicePower"] != false {
		t.Fatalf("profile alert: %+v", ms)
	}
}

// Noise, line ends, unknown report types and HEX-format frames are passed
// over with a warning; the frames around them are read.
//
// Covers: SIG-IMP-024
func TestLenientDecoding(t *testing.T) {
	hex := "+RSP\x10\x00\x01\x02\x03\r\n"
	ms, skips := decode(t, "", "\r\nnoise"+vFRI+"\r\n+RESP:GTXYZ,250301,135790246811220,,1,2,20090214093254,11F0$"+hex+vHBD)
	var got []string
	for _, m := range ms {
		if m == nil {
			got = append(got, "skip")
		} else {
			got = append(got, m.Kind)
		}
	}
	if strings.Join(got, " ") != "normal skip skip heartbeat" {
		t.Fatalf("frames %v", got)
	}
	var codes []string
	for _, e := range skips {
		var sk *track.Skip
		if errors.As(e, &sk) {
			codes = append(codes, sk.Code)
		}
	}
	if strings.Join(codes, " ") != "unknownMessage unknownCodec" {
		t.Fatalf("skip codes %v", codes)
	}
	// Known reports without values identify the device and record nothing.
	if m := one(t, "+RESP:GTPDP,250301,135790246811220,,20090214093254,11F0$"); len(m.Records) != 0 {
		t.Fatalf("GTPDP records %+v", m.Records)
	}
}

// imei is a device of the command tests.
const imei = "862170010196747"

// The serial numbers and the correlation of each command form.
//
// Covers: SIG-IMP-023
func TestCorrelation(t *testing.T) {
	codec, err := queclink.NewCodecForTest(`{"password": "gv300n"}`, 3)
	if err != nil {
		t.Fatal(err)
	}
	f, answers, err := codec.Command(imei, map[string]any{"action": "engineStop"}, 1)
	if err != nil || !answers || string(f) != "AT+GTOUT=gv300n,1,,,0,0,0,0,0,0,0,,,,,,,0004$" {
		t.Fatalf("frame %q %v %v", f, answers, err)
	}
	cr := codec.(track.Correlator)
	// The document's acknowledgement of serial 0004 names this command.
	ms, _ := decode(t, "", vAckOUT)
	if corr, strict := cr.Correlation(map[string]any{"action": "engineStop"}, 1); corr != ms[0].Correlation || !strict {
		t.Fatalf("correlation %q %v, ack %q", corr, strict, ms[0].Correlation)
	}
	if corr, strict := cr.Correlation(map[string]any{"text": "AT+GTRTO=gv300n,A,,,,,,0015$"}, 9); corr != "GTRTO/0015" || !strict {
		t.Fatalf("text correlation %q %v", corr, strict)
	}
	if corr, _ := cr.Correlation(map[string]any{"text": "AT+GTXYZ=1"}, 9); corr != "" {
		t.Fatalf("text without serial: %q", corr)
	}
	// A profile's text replaces the default; the serial is appended.
	codec, err = queclink.NewCodecForTest(`{"password": "pw", "namedCommands": {"engineStop": "AT+GTOUT={password},1,0,0,,,,,,,,,,,,,", "reboot": ""}}`, 0)
	if err != nil {
		t.Fatal(err)
	}
	if f, _, _ := codec.Command(imei, map[string]any{"action": "engineStop"}, 0x10); string(f) != "AT+GTOUT=pw,1,0,0,,,,,,,,,,,,,,0010$" {
		t.Fatalf("namedCommands frame %q", f)
	}
	if _, _, err := codec.Command(imei, map[string]any{"action": "reboot"}, 1); !errors.Is(err, track.ErrUnsupported) {
		t.Fatalf("turned-off action: %v", err)
	}
	for _, bad := range []string{`{"namedCommands": {"locate": "AT+GTRTO={password},1,,,,,,0001$"}}`, `{"namedCommands": {"locate": "RTO"}}`, `{"nope": 1}`} {
		if _, err := queclink.NewCodecForTest(bad, 0); err == nil {
			t.Errorf("profile %s accepted", bad)
		}
	}
}
