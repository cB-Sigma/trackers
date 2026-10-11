package ruptela_test

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/trackers/ruptela"
	"github.com/cB-Sigma/trackers/track"
)

func h(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

// Packets printed in Ruptela's protocol description (v1.113); each CRC was
// checked independently with the document's CRC-16 routine.
const (
	docRecordsAck   = "0002 64 01 13BC"
	docSMS          = "000A 6C 736574696F20322C31 59B9" // "setio 2,1"
	docSMSAnswer    = "0024 0003124D0AC0BB1C 07 534554494F20636F6E66696775726174696F6E2064617461206F6B C419"
	docHeartbeat    = "0009 000310F561749007 10 BD93"
	docHeartbeatAck = "0002 74 01 862D"
	docSetIO        = "0009 75 000000AF 00000064 39CC"
	docSetIOAnswer  = "000A 000310F56139B984 11 00 9799"
	docIdentAck     = "0002 73 01 CB25"
	// The first record of the document's records example (30 records,
	// 27 bytes each); the test frames it alone with the document's IMEI.
	docRecord = "5268CEF2 00 00 196E3A3A 0AEF3E93 4F3E 2D78 00 0000 00 07 00 00 00 00"
	docIMEI   = 0x00000C076B5C208F
)

// Packets captured from devices, as published in Traccar's decoder tests
// (Apache-2.0, see NOTICE); their CRCs were checked independently.
const (
	devRecords = "0050000310f5615f419c0100015613d8ed0000fff5b37a035af37801e700000900000d07071b0c020003001c01202cad000500064302a81d33e61e100116317cd3ffff174ad60241000077fa960000f232003c2e"
	devIdent   = "002e000316d53d58d6020f4573303430302e30332e36382e30340000c2b3090d0e950000827b000003e80000003c003c1681"
	devGetio   = "0044000313612d76c5cb0744494e313d312c44494e323d302c44494e333d302c44494e343d302c444f5554313d312c444f5554323d312c41494e313d31372c41494e323d3236ac80"
	devExt     = "01a4000315bc70f9b69244000458068f4a0030000d11398a1c0c19fd056524040b000c0a00090c0005010031f40032fd0033f200ce47002400002500001c010199000195010196010086000900aa0000001e0ff000d3ffff0043ffff01930000019200000194000002220000022300000200300000000200af000e872401008e000000000000000058068f4a0031000d11398a1c0c19fd056524040b000c0a00090400870000880000a90000820010008b0002021e0000021f0000021d0000021c0000022400000225000000890000008505f00220000002210000008300000084000002260000022700000228000003008a00000000008d00000000008c000000000058068f4a0032000d11398a1c0c19fd056524040b000c0a000905019f01005800001b1f00ad0000cfb10b02290000022a0000022b0000022c0000022d00000012000000130000001d367400c52f8000740055023e0502060097000000000096000058520041007746cb00d0000003f1005c0007c21b0072001864880058068f4a0033000d11398a1c0c19fd056524040b000c0a000900000001008e0000000000000000e815"
)

func decodeAll(t *testing.T, profile string, frames ...[]byte) []*track.Message {
	t.Helper()
	nc, err := ruptela.NewCodec(json.RawMessage(profile))
	if err != nil {
		t.Fatal(err)
	}
	c := nc()
	br := bufio.NewReader(bytes.NewReader(bytes.Join(frames, nil)))
	var out []*track.Message
	for {
		m, err := c.Decode(br)
		if errors.Is(err, track.ErrSkip) {
			out = append(out, nil)
			continue
		}
		if err != nil {
			return out
		}
		out = append(out, m)
	}
}

// Covers: SIG-IMP-029
func TestDocumentPackets(t *testing.T) {
	for _, v := range []string{docRecordsAck, docSMS, docSMSAnswer, docHeartbeat, docHeartbeatAck, docSetIO, docSetIOAnswer, docIdentAck} {
		b := h(v)
		if got := ruptela.CRC(b[2 : len(b)-2]); got != uint16(b[len(b)-2])<<8|uint16(b[len(b)-1]) {
			t.Errorf("CRC of %s: %04X", v, got)
		}
	}
	rec := ruptela.DeviceFrame(docIMEI, ruptela.CmdRecords, append([]byte{0, 1}, h(docRecord)...))
	ms := decodeAll(t, "", rec, h(docHeartbeat), h(docSMSAnswer), h(docSetIOAnswer))
	if len(ms) != 4 {
		t.Fatalf("decoded %d packets", len(ms))
	}
	m := ms[0]
	if m.IMEI != "13226005504143" || !bytes.Equal(m.Reply, h(docRecordsAck)) || len(m.Records) != 1 {
		t.Fatalf("records %+v % X", m, m.Reply)
	}
	r := m.Records[0]
	f := r.Fix
	if f.Time != time.Unix(0x5268CEF2, 0).UTC() || f.Lon != 42.6654266 || f.Lat != 18.3451283 || *f.Alt != 2028.6 || *f.Heading != 116.4 ||
		*f.Speed != 0 || f.Valid || r.History || r.Status["event"] != 7 {
		t.Fatalf("record %+v %v", f, r.Status)
	}
	if ms[1].IMEI != "863071018192903" || !bytes.Equal(ms[1].Reply, h(docHeartbeatAck)) {
		t.Fatalf("heartbeat %+v", ms[1])
	}
	if *ms[2].Response != "SETIO configuration data ok" || ms[2].Failed {
		t.Fatalf("SMS answer %q", *ms[2].Response)
	}
	if *ms[3].Response != "IO value changed" || ms[3].Failed {
		t.Fatalf("set IO answer %q", *ms[3].Response)
	}
	// The server's packets are the document's.
	if !bytes.Equal(ruptela.SMSFrame("setio 2,1"), h(docSMS)) || !bytes.Equal(ruptela.SetIOFrame(175, 100), h(docSetIO)) {
		t.Fatal("server packets differ from the document's")
	}
}

// Covers: SIG-IMP-029
func TestDevicePackets(t *testing.T) {
	ms := decodeAll(t, "", h(devIdent), h(devRecords), h(devExt), h(devGetio))
	if len(ms) != 4 {
		t.Fatalf("decoded %d packets", len(ms))
	}
	id := ms[0]
	if !id.Login || id.IMEI != "869530043209218" || !bytes.Equal(id.Reply, h(docIdentAck)) ||
		id.Records[0].Status["deviceType"] != "Es04" || id.Records[0].Status["firmware"] != "00.03.68.04" {
		t.Fatalf("identification %+v %v", id, id.Records)
	}
	r := ms[1].Records[0]
	st := r.Status
	if r.Fix.Time != time.Unix(0x5613d8ed, 0).UTC() || !r.Fix.Valid || *r.Fix.Sats != 9 || r.Fix.Lon != -0.067495 || r.Fix.Lat != 5.6292216 {
		t.Fatalf("fix %+v", r.Fix)
	}
	if st["ignition"] != false || st["din4"] != false || st["externalVoltage"] != 13.286 || st["batteryVoltage"] != 4.097 ||
		st["odometer"] != uint64(30714) || st["gsm"] != uint64(12) {
		t.Fatalf("status %v", st)
	}
	// Four headers with record extension 0x30..0x33 are one record.
	if n := len(ms[2].Records); n != 1 {
		t.Fatalf("extended records: %d", n)
	}
	e := ms[2].Records[0]
	if e.Status["ignition"] != true || e.Status["event"] != 9 || len(e.Status["io"].(map[string]any)) < 30 || !e.Fix.Valid || *e.Fix.Speed != 12 {
		t.Fatalf("extended %v %+v", e.Status, e.Fix)
	}
	if !strings.HasPrefix(*ms[3].Response, "DIN1=1,DIN2=0") || ms[3].Failed {
		t.Fatalf("getio answer %q", *ms[3].Response)
	}
}

// Event IDs name the IO element that made the record; they become alerts.
// Records sent while "records left" is set are history.
//
// Covers: SIG-IMP-029
func TestEventsAndHistory(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	recs := recordsPayload(true, true,
		rptRec{Time: now, Lat: 12.97, Lon: 77.59, Sats: 8, Event: 5, IO1: map[uint16]uint64{5: 1}},
		rptRec{Time: now, Lat: 12.97, Lon: 77.59, Sats: 8, Event: 134, IO1: map[uint16]uint64{134: 1}},
		rptRec{Time: now, Lat: 12.97, Lon: 77.59, Sats: 8, Event: 14})
	ms := decodeAll(t, `{"events": {"14": "emergency"}}`, ruptela.DeviceFrame(356307042441013, ruptela.CmdExtRecords, recs))
	if len(ms) != 1 || len(ms[0].Records) != 3 || ms[0].Kind != "emergency" {
		t.Fatalf("%+v", ms)
	}
	want := []string{"ignition-on", "harsh-braking", "emergency"}
	for i, r := range ms[0].Records {
		if len(r.Alerts) != 1 || r.Alerts[0].Type != want[i] || !r.History {
			t.Errorf("record %d: %+v history %v", i, r.Alerts, r.History)
		}
	}
	if _, err := ruptela.NewCodec(json.RawMessage(`{"events": {"x": "emergency"}}`)); err == nil {
		t.Fatal("a bad event ID was accepted")
	}
}

// Unknown commands and bad CRCs are passed over and the session reads on;
// checkCrc false accepts a bad CRC.
//
// Covers: SIG-IMP-032
func TestLenientParsing(t *testing.T) {
	version := ruptela.DeviceFrame(356307042441013, 3, []byte("FM-Pro4 00.02.24"))
	bad := h(docHeartbeat)
	bad[len(bad)-1] ^= 0xFF
	ms := decodeAll(t, "", version, bad, h(docHeartbeat))
	if len(ms) != 3 || ms[0] != nil || ms[1] != nil || ms[2] == nil {
		t.Fatalf("%v", ms)
	}
	ms = decodeAll(t, `{"checkCrc": false}`, bad)
	if len(ms) != 1 || ms[0] == nil {
		t.Fatal("checkCrc false refused the packet")
	}
	// Truncated record data is refused (NACK) without closing the session.
	short := ruptela.DeviceFrame(356307042441013, ruptela.CmdRecords, []byte{0, 2, 1, 2, 3})
	ms = decodeAll(t, "", short, h(docHeartbeat))
	if len(ms) != 2 || ms[0] == nil || !bytes.Equal(ms[0].Reply, ruptela.ServerFrame(ruptela.AckRecords, []byte{0})) || len(ms[0].Warnings) != 1 || ms[1] == nil {
		t.Fatalf("%+v", ms)
	}
	for _, p := range []string{`{"io": {"x": "y"}}`, `{"nope": 1}`, `{"namedCommands": {"fly": "x"}}`, `{"failureWords": [" "]}`} {
		if _, err := ruptela.NewCodec(json.RawMessage(p)); err == nil {
			t.Errorf("profile %s was accepted", p)
		}
	}
}

// The named commands' bytes, and a profile template replacing one.
//
// Covers: SIG-IMP-031
func TestNamedCommandBytes(t *testing.T) {
	nc, err := ruptela.NewCodec(json.RawMessage(`{"namedCommands": {"engineStop": "setio 1,2", "interval": "setcfg 1000 {seconds}"}}`))
	if err != nil {
		t.Fatal(err)
	}
	c := nc()
	for content, want := range map[string]string{
		`{"action":"engineStop"}`:            "setio 1,2",
		`{"action":"engineResume"}`:          "resetimmob",
		`{"action":"locate"}`:                "coords",
		`{"action":"reboot"}`:                "reset",
		`{"action":"interval","seconds":60}`: "setcfg 1000 60",
		`{"text":"getio"}`:                   "getio",
	} {
		var v any
		_ = json.Unmarshal([]byte(content), &v)
		f, answers, err := c.Command("356307042441013", v, 1)
		if err != nil || !answers || !bytes.Equal(f, ruptela.SMSFrame(want)) {
			t.Errorf("%s: % X %v %v", content, f, answers, err)
		}
	}
	if _, _, err := c.Command("1", map[string]any{"text": strings.Repeat("x", 161)}, 1); err == nil {
		t.Error("a 161-character command was accepted")
	}
}
