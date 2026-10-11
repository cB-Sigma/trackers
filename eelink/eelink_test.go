// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package eelink_test

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/trackers/eelink"
	"github.com/cB-Sigma/trackers/track"
)

// Packets marked "doc" are the examples of the EELINK Device Protocol V2.0;
// the others are from Traccar's EelinkProtocolDecoderTest and
// EelinkProtocolEncoderTest (Apache-2.0), used as test vectors only.

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newCodec(t *testing.T, profile string) track.Codec {
	t.Helper()
	nc, err := eelink.NewCodec(json.RawMessage(profile))
	if err != nil {
		t.Fatal(err)
	}
	return nc()
}

func decode(t *testing.T, c track.Codec, h string) *track.Message {
	t.Helper()
	m, err := c.Decode(bufio.NewReader(bytes.NewReader(unhex(t, h))))
	if err != nil {
		t.Fatalf("%s: %v", h, err)
	}
	return m
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-5 }

// Login 2.0 (doc): IMEI from the BCD terminal ID, versions, and the 2.0
// answer with server time, protocol version 1 and no param-set action.
func TestLogin20(t *testing.T) {
	c := newCodec(t, "")
	m := decode(t, c, "67670100180005035254407167747100200205020500010432000088BD")
	if !m.Login || m.IMEI != "352544071677471" || m.Kind != "login" {
		t.Fatalf("%+v", m)
	}
	r := m.Reply
	if len(r) != 14 || hex.EncodeToString(r[:7]) != "67670100090005" || hex.EncodeToString(r[11:]) != "000100" {
		t.Fatalf("reply %x", r)
	}
	if d := time.Since(time.Unix(int64(uint32(r[7])<<24|uint32(r[8])<<16|uint32(r[9])<<8|uint32(r[10])), 0)); d < -time.Minute || d > time.Minute {
		t.Fatalf("reply time %x", r[7:11])
	}
	st := m.Records[0].Status
	if st["language"] != "zh" || st["timezoneMinutes"] != 480 || st["systemVersion"] != "2.0.5" || st["appVersion"] != "2.0.5" {
		t.Fatalf("status %v", st)
	}
}

// Login 1.x (IMEI and language only) is answered with an empty package.
func TestLogin1x(t *testing.T) {
	c := newCodec(t, "")
	m := decode(t, c, "676701000b001b035418804661834901")
	if !m.Login || m.IMEI != "354188046618349" || hex.EncodeToString(m.Reply) != "6767010002001b" {
		t.Fatalf("%+v %x", m, m.Reply)
	}
}

// Heartbeat (doc) carries the status word and is answered.
func TestHeartbeat(t *testing.T) {
	c := newCodec(t, "")
	m := decode(t, c, "676703000400070188")
	if hex.EncodeToString(m.Reply) != "67670300020007" || m.Kind != "heartbeat" {
		t.Fatalf("%+v %x", m, m.Reply)
	}
	st := m.Records[0].Status
	if st["charging"] != true || st["statusWord"] != 0x0188 {
		t.Fatalf("%v", st)
	}
	m = decode(t, c, "6767030004001A0001")
	if _, ok := m.Records[0].Status["ignition"]; ok {
		t.Fatalf("ignition from a device not made for cars: %v", m.Records[0].Status)
	}
}

// Location 0x12 (doc): fix, home cell, status word, battery and mileage;
// not answered over TCP unless ackLocation.
func TestLocation(t *testing.T) {
	const pkt = "67671200410022590BD94203026B940D0C3952AD0021000000000001CC0001A53F0170F0AB1301890F08000000000000C2D0001C001600000000000000000000000000000000"
	c := newCodec(t, "")
	m := decode(t, c, pkt)
	if m.Reply != nil || m.Kind != "location" || len(m.Records) != 1 {
		t.Fatalf("%+v", m)
	}
	r := m.Records[0]
	f := r.Fix
	if !f.Valid || !f.Time.Equal(time.Unix(0x590BD942, 0)) || !near(f.Lat, 40604685/1800000.0) || !near(f.Lon, 0x0C3952AD/1800000.0) ||
		*f.Alt != 33 || *f.Speed != 0 || *f.Sats != 0 {
		t.Fatalf("fix %+v", f)
	}
	cell := r.Network.Cells[0]
	if cell.MCC != 460 || cell.MNC != 1 || cell.LAC != 0xA53F || cell.CID != 0x0170F0AB || *cell.RSSI != 19-110 {
		t.Fatalf("cell %+v", cell)
	}
	if r.Status["batteryVoltage"] != 3.848 || r.Status["odometer"] != 49872 || r.Status["charging"] != true {
		t.Fatalf("status %v", r.Status)
	}
	c = newCodec(t, `{"ackLocation": true}`)
	if m := decode(t, c, pkt); hex.EncodeToString(m.Reply) != "67671200020022" {
		t.Fatalf("reply %x", m.Reply)
	}
}

// Warning 0x14 (doc, SOS) and report 0x15 (doc, ACC off) are answered.
func TestWarningAndReport(t *testing.T) {
	c := newCodec(t, "")
	m := decode(t, c, "6767140024000A590BD54903026B940D0C3952AD0021000400000501CC0001A53F0170F0AB19020789")
	r := m.Records[0]
	if hex.EncodeToString(m.Reply) != "6767140002000a" || len(r.Alerts) != 1 || r.Alerts[0].Type != "emergency" || r.Alerts[0].Severity != track.Critical ||
		*r.Fix.Speed != 4 || *r.Fix.Sats != 5 {
		t.Fatalf("%+v %+v", m, r)
	}
	m = decode(t, c, "6767150024000B590BD57103026B940D0C3952AD0021000000000501CC0001A53F0170F0AB18020789")
	r = m.Records[0]
	if hex.EncodeToString(m.Reply) != "6767150002000b" || len(r.Alerts) != 1 || r.Alerts[0].Type != "ignition-off" || r.Status["ignition"] != false {
		t.Fatalf("%+v %+v", m, r)
	}
	// A warning without GPS (cell only), code 0x25.
	m = decode(t, c, "676714001500035f74a2940201360104591100a7160122250400")
	r = m.Records[0]
	if r.Fix != nil || r.Network == nil || len(r.Alerts) != 1 || r.Alerts[0].Code != "0x25" {
		t.Fatalf("%+v", r)
	}
}

// Message 0x16 (doc): the phone number and SMS text, answered with the
// number and an empty result.
func TestMessage(t *testing.T) {
	c := newCodec(t, "")
	m := decode(t, c, "6767160039000D590BD5AF03026B940D0C3952AD0021000000000501CC0001A53F0170F0AB17323031383536363232313235300000000000000000313233")
	r := m.Records[0]
	if r.Status["smsFrom"] != "2018566221250" || r.Status["smsText"] != "123" {
		t.Fatalf("%v", r.Status)
	}
	want := "67670100"[:0] + "6767160017000d" + hex.EncodeToString(append([]byte("2018566221250"), make([]byte, 8)...))
	if hex.EncodeToString(m.Reply) != want {
		t.Fatalf("reply %x want %s", m.Reply, want)
	}
}

// Extended position (mask bit 7, LTE cell and WiFi list) and many
// records in one UDP datagram.
func TestExtendedAndDatagram(t *testing.T) {
	c := newCodec(t, "")
	m := decode(t, c, "676714006d00046a957abe810494e677028025930230000000000b0749011c0001044d044d007bf2f1000000840b86ba6c4cbcbe56e5c51062eb445737c2f068e364459cc118a6f767de30c07054f57e0690bccebabd26f96ebc50a9dea1e391bacebabd271d3eb47c7d21cb5297b8250409")
	r := m.Records[0]
	if r.Fix == nil || r.Network == nil || len(r.Network.Cells) != 1 || len(r.Network.WiFi) == 0 {
		t.Fatalf("%+v %+v", r, r.Network)
	}
	dc := newCodec(t, "").(track.DatagramCodec)
	ms, err := dc.DecodeDatagram(unhex(t, "454c029249a50354679090044671676712004321315f3cf43503fc94d3760c79328a0129000000000a01f9000190330905580d2e046f118a04ec00000000ccc7086c02fe000000000000000000000000000000000000676712004321325f3cf43e03fc94d3760c79328a0129000000000901f9000190330905580d2e046f117b04ec00000000ccc7086d02ff000000000000000000000000000000000000676712004321335f3cf44703fc94d3760c79328a0129000000000901f9000190330905580d2e046f117f04ec00000000ccc7086d02ff000000000000000000000000000000000000676712004321345f3cf45303fc94d3760c79328a0129000000000901f9000190330905580d2e046f119d04ec00000000ccc7086d02ff000000000000000000000000000000000000676712004321355f3cf45c03fc94d3760c79328a0129000000000801f9000190330905580d2e046f11a304ec00000000ccc7086d02ff000000000000000000000000000000000000676712004321365f3cf46603fc94d3760c79328a0129000000000801f9000190330905580d2e046f118804df00000000ccc7086d02ff000000000000000000000000000000000000676712004321375f3cf47103fc94d3760c79328a0129000000000901f9000190330905580d2e046f119704ec00000000ccc7086d02ff000000000000000000000000000000000000676712004321385f3cf47a03fc94d3760c79328a0129000000000901f9000190330905580d2e046f118204ec00000000ccc7086e0300000000000000000000000000000000000000676712004321395f3cf48303fc94d3760c79328a0129000000000901f9000190330905580d2e046f117604df00000000ccc7086e0300000000000000000000000000000000000000"))
	if err != nil || len(ms) != 9 {
		t.Fatalf("%d %v", len(ms), err)
	}
	// Over UDP every location is answered, inside a UDP header.
	if ms[0].IMEI != "354679090044671" || len(ms[0].Reply) < 14 || string(ms[0].Reply[:2]) != "EL" {
		t.Fatalf("%+v %x", ms[0], ms[0].Reply)
	}
	// A datagram whose checksum does not match is refused.
	if _, err := dc.DecodeDatagram(unhex(t, "454C0027E754035254407167747167670100180002035254407167747100200205020500010432000086BD")); err == nil {
		t.Fatal("bad checksum accepted")
	}
	ms, err = dc.DecodeDatagram(unhex(t, "454C0027E753035254407167747167670100180002035254407167747100200205020500010432000086BD"))
	if err != nil || len(ms) != 1 || !ms[0].Login || ms[0].IMEI != "352544071677471" {
		t.Fatalf("%+v %v", ms, err)
	}
}

// 1.x packets: GPS 0x02 (not answered), alarm 0x04 and state 0x05
// (answered).
func TestOldPackets(t *testing.T) {
	c := newCodec(t, "")
	m := decode(t, c, "676702001b03c5538086df0190c1790b3482df0f0157020800013beb00342401")
	r := m.Records[0]
	if m.Reply != nil || r.Fix == nil || !r.Fix.Valid || *r.Fix.Speed != 0x0f || r.Network.Cells[0].MCC != 0x0208 {
		t.Fatalf("%+v %+v", m, r.Fix)
	}
	m = decode(t, c, "676704001c01a4569ff2dd0517a0f7020b0d9a06011000d8001e005b0004450183")
	if hex.EncodeToString(m.Reply) != "676704000201a4" || len(m.Records[0].Alerts) != 1 || m.Records[0].Alerts[0].Type != "geofence-enter" {
		t.Fatalf("%+v %x", m.Records[0], m.Reply)
	}
	m = decode(t, c, "676705002200ba569fc3520517a0d8020b0f740f007100d8001e005b0004460101569fd162001f")
	r = m.Records[0]
	if hex.EncodeToString(m.Reply) != "676705000200ba" || r.Status["ignition"] != true || len(r.Alerts) != 1 || r.Alerts[0].Type != "ignition-on" {
		t.Fatalf("%+v %x", r, m.Reply)
	}
}

// The device's answer to an instruction: its result text, the UID it
// repeats as correlation, and a position when it answers WHERE.
func TestInstructionAnswer(t *testing.T) {
	c := newCodec(t, "")
	m := decode(t, c, "676780005a000001000000004c61743a4e33312e38333935352c4c6f6e3a5738322e36313334362c436f757273653a302e30302c53706565643a302e30306b6d2f682c4461746554696d653a323031372d31322d30322031313a32393a3433")
	if m.Response == nil || !strings.HasPrefix(*m.Response, "Lat:N31.83955") || m.Correlation != "" || m.Kind != "response" || len(m.Records) != 1 {
		t.Fatalf("%+v", m)
	}
	f := m.Records[0].Fix
	if !near(f.Lat, 31.83955) || !near(f.Lon, -82.61346) || !f.Time.Equal(time.Date(2017, 12, 2, 11, 29, 43, 0, time.UTC)) {
		t.Fatalf("%+v", f)
	}
	m = decode(t, c, "676780005E5788014C754C754C61743A4E32332E3131313734330A4C6F6E3A453131342E3430393233380A436F757273653A302E30300A53706565643A302E31374B4D2F480A446174652054696D653A323031352D30392D31332032303A32313A3230")
	if m.Correlation != "1282755701" || len(m.Records) != 1 || !near(m.Records[0].Fix.Lon, 114.409238) {
		t.Fatalf("%+v", m)
	}
	m = decode(t, c, "676780000e000501000000074572726f722121")
	if !m.Failed || m.Correlation != "7" {
		t.Fatalf("%+v", m)
	}
}

// Commands: 0x80 with type 1, the sequence as UID, the command text.
func TestCommand(t *testing.T) {
	c := newCodec(t, "")
	f, answers, err := c.Command("123456789012345", map[string]any{"action": "engineStop"}, 0)
	if err != nil || !answers || hex.EncodeToString(f) != "676780000f0000010000000052454c41592c3123" {
		t.Fatalf("%x %v %v", f, answers, err)
	}
	for content, want := range map[string]string{
		`{"action": "engineResume"}`:            "RELAY,0#",
		`{"action": "locate"}`:                  "WHERE#",
		`{"action": "reboot"}`:                  "RESET#",
		`{"action": "interval", "seconds": 60}`: "COLLECT,60,0,0,0,1#",
		`{"text": "STATUS#"}`:                   "STATUS#",
	} {
		var v any
		_ = json.Unmarshal([]byte(content), &v)
		f, _, err := c.Command("123456789012345", v, 0x01020304)
		if err != nil || string(f[12:]) != want || hex.EncodeToString(f[7:12]) != "0101020304" {
			t.Errorf("%s: %q %v", content, f, err)
		}
		if corr, strict := c.(track.Correlator).Correlation(v, 0x01020304); corr != "16909060" || strict {
			t.Errorf("%s: %q", content, corr)
		}
	}
	// After a datagram the codec frames commands for UDP.
	dc := newCodec(t, "")
	if _, err := dc.(track.DatagramCodec).DecodeDatagram(unhex(t, "454C0027E753035254407167747167670100180002035254407167747100200205020500010432000086BD")); err != nil {
		t.Fatal(err)
	}
	f, _, err = dc.Command("123456789012345", map[string]any{"action": "engineStop"}, 0)
	if err != nil || hex.EncodeToString(f) != "454c001eb41a0123456789012345676780000f0000010000000052454c41592c3123" || !dc.(track.DatagramCommander).DatagramCommands() {
		t.Fatalf("%x %v", f, err)
	}
	if _, err := eelink.NewCodec(json.RawMessage(`{"namedCommands": {"x": "y"}}`)); err == nil {
		t.Fatal("bad named command accepted")
	}
	if _, err := eelink.NewCodec(json.RawMessage(`{"alarms": {"zz": "x"}}`)); err == nil {
		t.Fatal("bad alarm code accepted")
	}
}

// Noise before a package is skipped; an unknown package is answered and
// passed over with a warning.
func TestResyncAndUnknown(t *testing.T) {
	c := newCodec(t, "")
	r := bufio.NewReader(bytes.NewReader(unhex(t, "0102676703000400070188"+"67671b0004000901ff")))
	m, err := c.Decode(r)
	if err != nil || m.Kind != "heartbeat" {
		t.Fatalf("%+v %v", m, err)
	}
	_, err = c.Decode(r)
	var sk *track.Skip
	if !errors.As(err, &sk) || sk.Code != "unknownPacket" || hex.EncodeToString(sk.Reply) != "67671b00020009" {
		t.Fatalf("%v", err)
	}
	if _, err := c.Decode(r); !errors.Is(err, io.EOF) {
		t.Fatalf("%v", err)
	}
}
