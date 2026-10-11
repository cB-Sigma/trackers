// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package wialon_test

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/trackers/track"
	"github.com/cB-Sigma/trackers/wialon"
)

func h(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

// Packets printed in Gurtam's "Wialon IPS" v2.0 description (compressed
// packet examples, hex and text).
const (
	docCompressedLogin = "FF1B00780153F65136D233B0CECC4DCDB4F673B476B4343602002FF404E6"
	docLoginText       = "#L#2.0;imei;NA;A932"
	docCompressedData  = "FF76007801258CCB0AC24010043F26D77599DE9931ECF4C9D7351EF2050145024625F8FF9818EA540DD5CDB9290A41215CAB57BABA65AB652FEC28A55564B35A8517CA828AB02532FE86242BEC0E1C1FAF4020DD3EC33C4C5142330CBE1C79FA6E9BC6F33DDFA7346E8AD8B9A7FEDAAF1DED78D21FEF7522F7"
)

// Packets captured from devices, as published in Traccar's decoder tests
// (Apache-2.0, see NOTICE).
const (
	devLogin20  = "#L#2.0;42001300083;;CE45"
	devSD20     = "#SD#300924;154245;5554.350052;N;3644.670410;E;2.92;NA;NA;NA;7A01"
	devD20      = "#D#220323;114150;2234.80479;N;11354.87786;E;0;NA;59;11;NA;NA;NA;;NA;d_battr:1:94,d_csq:1:21,di_light:1:1;E7C9"
	devD20NoFix = "#D#120319;112003;NA;NA;NA;NA;0.000;NA;NA;0;NA;NA;NA;NA;NA;101_521347:1:521246,101_158:1:510,101_521055:1:510,101_521055_2.9:1:509,101_521056:1:3;626B"
	devLogin11  = "#L#123456789012345;test"
	devLogin11b = "#L#2002;NA"
	devPing     = "#P#"
	devUDP20    = "2.0;99999999#D#101118;061143;0756.0930;N;12338.6403;E;18.223;99.766;-4.000;10;0.800;NA;NA;NA;NA;101_521347:1:521249,101_521126:1:6593598,101_521127:1:774780,101_521072_21.1:1:0,101_521072_21.2:1:71353;F24A"
	devSD11     = "#SD#270413;205601;5544.6025;N;03739.6834;E;1;2;3;4"
	devUDP11    = "99999999#SD#270413;205601;5544.6025;N;03739.6834;E;1;2;3;4"
	devSDEmpty  = "#SD#021214;065947;2237.7552;N;11404.8851;E;0.000;;170.9;5"
	devD11      = "#D#270413;205601;5544.6025;N;03739.6834;E;1;2;3;4;0.0;0;0;14.77,0.02,3.6;NA;count1:1:564,fuel:2:45.8,hw:3:V4.5"
	devB11      = "#B#080914;073235;5027.50625;N;03026.19321;E;0.700;0.000;NA;4;NA;NA;NA;;NA;Батарея:3:100 %|080914;073420;5027.50845;N;03026.18854;E;1.996;292.540;NA;4;NA;NA;NA;;NA;Батарея:3:100 %"
	devB11Adc   = "#B#110315;045857;5364.0167;N;06127.8262;E;0;155;965;7;2.40;4;0;14.77,0.02,3.6;AB45DF01145;"
	devDMotion  = "#D#120319;112003;NA;NA;NA;NA;0.000;NA;NA;0;NA;NA;NA;NA;NA;motion:3:false"
	devDCells   = "#D#NA;NA;NA;NA;NA;NA;NA;NA;NA;NA;NA;NA;NA;;NA;mnc1:1:02,mcc1:1:250,lac1:1:5901,cell_id1:1:45542,mnc2:1:22,mcc2:1:222,lac2:1:2222,cell_id2:1:22222,mcc3:1:333"
	devDSOS     = "#D#NA;NA;NA;NA;NA;NA;NA;NA;NA;NA;NA;NA;NA;;NA;SOS:1:1,temp:3:18,bat:3:99"
)

func newCodec(t *testing.T, profile string) track.Codec {
	t.Helper()
	nc, err := wialon.NewCodec(json.RawMessage(profile))
	if err != nil {
		t.Fatal(err)
	}
	return nc()
}

// decode runs frames (each ended with \r\n here) through one codec.
func decode(t *testing.T, c track.Codec, frames ...string) ([]*track.Message, []error) {
	t.Helper()
	var b bytes.Buffer
	for _, f := range frames {
		b.WriteString(f + "\r\n")
	}
	return decodeBytes(c, b.Bytes())
}

func decodeBytes(c track.Codec, b []byte) ([]*track.Message, []error) {
	br := bufio.NewReader(bytes.NewReader(b))
	var out []*track.Message
	var errs []error
	for {
		m, err := c.Decode(br)
		if err == io.EOF {
			return out, errs
		}
		if err != nil && !errors.Is(err, track.ErrSkip) {
			errs = append(errs, err)
			return out, errs
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		out = append(out, m)
	}
}

func one(t *testing.T, profile, frame string) *track.Message {
	t.Helper()
	ms, errs := decode(t, newCodec(t, profile), frame)
	if len(errs) > 0 || len(ms) != 1 {
		t.Fatalf("%s: %v %v", frame, ms, errs)
	}
	return ms[0]
}

func near(a, b float64) bool { return a-b < 1e-5 && b-a < 1e-5 }

// The CRC is CRC-16/ARC over the text between the packet type and the
// checksum field, as the document's example shows.
func TestCRC(t *testing.T) {
	if got := wialon.CRC([]byte("2.0;imei;NA;")); got != 0xA932 {
		t.Fatalf("crc %04X", got)
	}
}

func TestLogin(t *testing.T) {
	for _, tc := range []struct {
		frame, imei, secret string
	}{
		{docLoginText, "imei", ""},
		{devLogin11, "123456789012345", "test"},
		{devLogin11b, "2002", ""},
	} {
		m := one(t, "", tc.frame)
		if !m.Login || m.IMEI != tc.imei || m.Secret != tc.secret || string(m.Reply) != "#AL#1\r\n" || string(m.Reject) != "#AL#0\r\n" {
			t.Fatalf("%s: %+v", tc.frame, m)
		}
	}
}

func TestBadCRC(t *testing.T) {
	c := newCodec(t, "")
	_, errs := decode(t, c, "#L#2.0;imei;NA;A933", "#SD#300924;154245;5554.350052;N;3644.670410;E;2.92;NA;NA;NA;7A02")
	var sk *track.Skip
	if len(errs) != 2 || !errors.As(errs[0], &sk) || sk.Code != "crcMismatch" || string(sk.Reply) != "#AL#10\r\n" {
		t.Fatalf("%v", errs)
	}
	if !errors.As(errs[1], &sk) || string(sk.Reply) != "#ASD#13\r\n" {
		t.Fatalf("%v", errs)
	}
	// checkCrc false takes it. The login of Traccar's test does not match
	// its CRC (every other 2.0 packet there does).
	for _, f := range []string{"#L#2.0;imei;NA;A933", devLogin20} {
		m := one(t, `{"checkCrc": false}`, f)
		if !m.Login || len(m.Warnings) != 1 || m.Warnings[0].Code != "crcMismatch" {
			t.Fatalf("%+v", m)
		}
	}
}

func TestShortData(t *testing.T) {
	m := one(t, "", devSD11)
	f := m.Records[0].Fix
	want := time.Date(2013, 4, 27, 20, 56, 1, 0, time.UTC)
	if string(m.Reply) != "#ASD#1\r\n" || !f.Time.Equal(want) || !f.Valid || !near(f.Lat, 55.743375) || !near(f.Lon, 37.66139) ||
		*f.Speed != 1 || *f.Heading != 2 || *f.Alt != 3 || *f.Sats != 4 {
		t.Fatalf("%+v %+v", m, f)
	}
	m = one(t, "", devSD20)
	f = m.Records[0].Fix
	if f == nil || !near(f.Lat, 55+54.350052/60) || !near(f.Lon, 36+44.670410/60) || *f.Speed != 2.92 || f.Heading != nil || f.Sats != nil {
		t.Fatalf("%+v", f)
	}
	m = one(t, "", devSDEmpty)
	if f := m.Records[0].Fix; f == nil || f.Heading != nil || *f.Alt != 170.9 {
		t.Fatalf("%+v", f)
	}
}

func TestExtendedData(t *testing.T) {
	m := one(t, "", devD20)
	r := m.Records[0]
	p := r.Status["params"].(map[string]any)
	if string(m.Reply) != "#AD#1\r\n" || r.Fix == nil || *r.Fix.Alt != 59 || *r.Fix.Sats != 11 || p["di_light"] != int64(1) || p["d_battr"] != int64(94) {
		t.Fatalf("%+v", r)
	}
	m = one(t, "", devD11)
	r = m.Records[0]
	p = r.Status["params"].(map[string]any)
	if *r.Fix.HDOP != 0 || r.Status["inputs"] != int64(0) || r.Status["adc1"] != 14.77 || r.Status["adc3"] != 3.6 ||
		p["count1"] != int64(564) || p["fuel"] != 45.8 || p["hw"] != "V4.5" {
		t.Fatalf("%+v", r.Status)
	}
	// Without a position the record carries no fix; its time is the server's.
	m = one(t, "", devD20NoFix)
	r = m.Records[0]
	if r.Fix != nil || r.Time.Year() != 2019 || r.Status["params"].(map[string]any)["101_521055_2.9"] != int64(509) {
		t.Fatalf("%+v", r)
	}
	m = one(t, "", devDMotion)
	if m.Records[0].Status["params"].(map[string]any)["motion"] != "false" {
		t.Fatalf("%+v", m.Records[0].Status)
	}
	m = one(t, "", devDCells)
	n := m.Records[0].Network
	if n == nil || len(n.Cells) != 2 || n.Cells[0] != (track.Cell{MCC: 250, MNC: 2, LAC: 5901, CID: 45542}) || n.Cells[1].CID != 22222 {
		t.Fatalf("%+v", n)
	}
	if time.Since(m.Records[0].Time) > time.Minute {
		t.Fatalf("time %v", m.Records[0].Time)
	}
	m = one(t, "", devDSOS)
	if a := m.Records[0].Alerts; len(a) != 1 || a[0].Type != "emergency" || m.Kind != "emergency" {
		t.Fatalf("%+v", m)
	}
	// A profile maps params to status names and alerts.
	m = one(t, `{"params": {"temp": "deviceTemp"}, "alarms": {"bat": "low-battery"}}`, devDSOS)
	if m.Records[0].Status["deviceTemp"] != "18" || len(m.Records[0].Alerts) != 2 {
		t.Fatalf("%+v", m.Records[0])
	}
}

func TestBlackBox(t *testing.T) {
	m := one(t, "", devB11)
	if len(m.Records) != 2 || string(m.Reply) != "#AB#2\r\n" || !m.Records[0].History || m.Records[1].Fix.Heading == nil {
		t.Fatalf("%+v", m)
	}
	if m.Records[0].Status["params"].(map[string]any)["Батарея"] != "100 %" {
		t.Fatalf("%+v", m.Records[0].Status)
	}
	m = one(t, "", devB11Adc)
	if len(m.Records) != 1 || m.Records[0].Status["driverId"] != "AB45DF01145" || *m.Records[0].Fix.HDOP != 2.4 {
		t.Fatalf("%+v", m.Records)
	}
	// Version 2.0: the data ends with "|" and the CRC.
	body := "270413;205601;5544.6025;N;03739.6834;E;1;2;3;4|270413;205602;5544.6025;N;03739.6834;E;1;2;3;4|"
	m = one(t, "", fmt.Sprintf("#B#%s%04X", body, wialon.CRC([]byte(body))))
	if len(m.Records) != 2 || string(m.Reply) != "#AB#2\r\n" {
		t.Fatalf("%+v", m)
	}
}

func TestPingAndUDPForm(t *testing.T) {
	m := one(t, "", devPing)
	if string(m.Reply) != "#AP#\r\n" || m.Kind != "health" {
		t.Fatalf("%+v", m)
	}
	for _, f := range []string{devUDP20, devUDP11} {
		m = one(t, "", f)
		if m.IMEI != "99999999" || len(m.Records) != 1 || m.Records[0].Fix == nil {
			t.Fatalf("%s: %+v", f, m)
		}
	}
	c := newCodec(t, "")
	ms, err := c.(track.DatagramCodec).DecodeDatagram([]byte(devUDP20 + "\r\n"))
	if err != nil || len(ms) != 1 || ms[0].IMEI != "99999999" || string(ms[0].Reply) != "#AD#1\r\n" || !near(ms[0].Records[0].Fix.Lat, 7+56.0930/60) {
		t.Fatalf("%+v %v", ms, err)
	}
}

func TestCompressed(t *testing.T) {
	c := newCodec(t, "")
	ms, errs := decodeBytes(c, append(h(docCompressedLogin), h(docCompressedData)...))
	if len(errs) != 0 || len(ms) != 2 || !ms[0].Login || ms[0].IMEI != "imei" {
		t.Fatalf("%+v %v", ms, errs)
	}
	r := ms[1].Records[0]
	if r.Fix == nil || !near(r.Fix.Lat, 53+54.49260/60) || r.Status["params"].(map[string]any)["dparam"] != 3.14159265 ||
		len(r.Alerts) != 1 || r.Alerts[0].Type != "emergency" {
		t.Fatalf("%+v", r)
	}
}

func TestDriverMessageAndCommands(t *testing.T) {
	c := newCodec(t, "")
	ms, _ := decode(t, c, docLoginText, "#M#Arrived;"+fmt.Sprintf("%04X", wialon.CRC([]byte("Arrived;"))))
	m := ms[1]
	if m.Response == nil || *m.Response != "Arrived" || string(m.Reply) != "#AM#1\r\n" || m.Records[0].Status["driverMessage"] != "Arrived" {
		t.Fatalf("%+v", m)
	}
	b, answers, err := c.Command("imei", map[string]any{"message": "Go to depot"}, 1)
	if err != nil || answers || string(b) != fmt.Sprintf("#M#Go to depot;%04X\r\n", wialon.CRC([]byte("Go to depot;"))) {
		t.Fatalf("%q %v %v", b, answers, err)
	}
	b, answers, err = c.Command("imei", map[string]any{"text": "getstatus"}, 2)
	if err != nil || !answers || string(b) != "getstatus\r\n" {
		t.Fatalf("%q %v %v", b, answers, err)
	}
	b, _, err = c.Command("imei", map[string]any{"snapshot": true}, 3)
	if err != nil || string(b) != "#QI#\r\n" {
		t.Fatalf("%q %v", b, err)
	}
	b, _, err = c.Command("imei", map[string]any{"ddd": "D123"}, 3)
	if err != nil || string(b) != "#QT#D123\r\n" {
		t.Fatalf("%q %v", b, err)
	}
	b, _, err = c.Command("imei", map[string]any{"firmware": "AAEC"}, 3)
	if err != nil || !bytes.Equal(b, append([]byte(fmt.Sprintf("#US#3;%04X\r\n", wialon.CRC([]byte{0, 1, 2}))), 0, 1, 2)) {
		t.Fatalf("%q %v", b, err)
	}
	_, _, err = c.Command("imei", map[string]any{"text": "a\r\nb"}, 3)
	if err == nil {
		t.Fatal("line break accepted")
	}
	// Named commands: none in the protocol; a profile template is sent as a
	// custom command.
	_, _, err = c.Command("imei", map[string]any{"action": "reboot"}, 4)
	if !errors.Is(err, track.ErrUnsupported) {
		t.Fatalf("%v", err)
	}
	c = newCodec(t, `{"namedCommands": {"interval": "setinterval {seconds}"}, "commandAnswers": false}`)
	b, answers, err = c.Command("imei", map[string]any{"action": "interval", "seconds": 60.0}, 5)
	if err != nil || answers || string(b) != "setinterval 60\r\n" {
		t.Fatalf("%q %v %v", b, answers, err)
	}
	// Version 1.1 devices take #M# without a CRC.
	c = newCodec(t, "")
	_, _ = decode(t, c, devLogin11)
	b, _, _ = c.Command("123456789012345", map[string]any{"message": "hi"}, 1)
	if string(b) != "#M#hi\r\n" {
		t.Fatalf("%q", b)
	}
	// An answer with a failure word fails the command.
	_, _ = decode(t, c, "#M#ERROR unknown command")
	ms, _ = decode(t, c, "#M#ERROR unknown command")
	if !ms[0].Failed {
		t.Fatalf("%+v", ms[0])
	}
}

func imagePacket(name string, ind, last int, blk []byte) []byte {
	head := fmt.Sprintf("#I#%d;%d;%d;111026;101500;%s;%04X\r\n", len(blk), ind, last, name, wialon.CRC(blk))
	return append([]byte(head), blk...)
}

func TestImage(t *testing.T) {
	c := newCodec(t, "")
	var b []byte
	b = append(b, []byte(docLoginText+"\r\n")...)
	b = append(b, imagePacket("cam.jpg", 0, 1, []byte{0xFF, 0xD8, 0x0D, 0x0A})...)
	b = append(b, imagePacket("cam.jpg", 1, 1, []byte{0xFF, 0xD9})...)
	ms, errs := decodeBytes(c, b)
	if len(errs) != 0 || len(ms) != 3 || string(ms[1].Reply) != "#AI#0;1\r\n" || string(ms[2].Reply) != "#AI#1\r\n" {
		t.Fatalf("%+v %v", ms, errs)
	}
	st := ms[2].Records[0].Status
	if !bytes.Equal(st["image"].([]byte), []byte{0xFF, 0xD8, 0x0D, 0x0A, 0xFF, 0xD9}) || st["imageName"] != "cam.jpg" ||
		!ms[2].Records[0].Time.Equal(time.Date(2026, 10, 11, 10, 15, 0, 0, time.UTC)) {
		t.Fatalf("%+v", st)
	}
}

func TestTachographFile(t *testing.T) {
	c := newCodec(t, "")
	info := "111026;101500;D42;;2;"
	blk := func(ind int, d []byte) []byte {
		return append([]byte(fmt.Sprintf("#T#;%d;%d;%04X\r\n", len(d), ind, wialon.CRC(d))), d...)
	}
	var b []byte
	b = append(b, []byte(fmt.Sprintf("#L#2.0;imei;NA;A932\r\n#IT#%s%04X\r\n", info, wialon.CRC([]byte(info))))...)
	b = append(b, blk(0, []byte("abc"))...)
	b = append(b, blk(1, []byte("def"))...)
	ms, errs := decodeBytes(c, b)
	if len(errs) != 0 || len(ms) != 4 || string(ms[1].Reply) != "#AIT#1\r\n" || string(ms[2].Reply) != "#AT#0;1\r\n" || string(ms[3].Reply) != "#AT#1\r\n" {
		t.Fatalf("%+v %v", ms, errs)
	}
	st := ms[3].Records[0].Status
	if string(st["ddd"].([]byte)) != "abcdef" || st["dddName"] != "D42_20261011_101500.ddd" || st["driverId"] != "D42" {
		t.Fatalf("%+v", st)
	}
}

func TestProfileAndUnknown(t *testing.T) {
	for _, p := range []string{`{"nope": 1}`, `{"version": "3.0"}`, `{"namedCommands": {"fly": "x"}}`} {
		if _, err := wialon.NewCodec(json.RawMessage(p)); err == nil {
			t.Fatalf("%s accepted", p)
		}
	}
	_, errs := decode(t, newCodec(t, ""), "#ZZ#hello", "garbage")
	var sk *track.Skip
	if len(errs) != 2 || !errors.As(errs[0], &sk) || sk.Code != "unknownMessage" {
		t.Fatalf("%v", errs)
	}
	// A broken data packet is answered with the protocol's error code.
	_, errs = decode(t, newCodec(t, ""), "#D#1;2;3")
	if len(errs) != 1 || !errors.As(errs[0], &sk) || string(sk.Reply) != "#AD#-1\r\n" {
		t.Fatalf("%v", errs)
	}
	_, errs = decode(t, newCodec(t, ""), "#SD#320413;205601;5544.6025;N;03739.6834;E;1;2;3;4")
	if len(errs) != 1 || !errors.As(errs[0], &sk) || string(sk.Reply) != "#ASD#0\r\n" {
		t.Fatalf("%v", errs)
	}
	if len(wialon.NamedActions) != 0 {
		t.Fatal(wialon.NamedActions)
	}
}

// The compressed container: 0xFF, a little-endian length and zlib data.
func TestCompressFrame(t *testing.T) {
	z := wialon.Compress([]byte(devSD11 + "\r\n"))
	if z[0] != 0xFF || int(binary.LittleEndian.Uint16(z[1:3])) != len(z)-3 {
		t.Fatalf("% x", z)
	}
	zr, err := zlib.NewReader(bytes.NewReader(z[3:]))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(zr)
	if string(b) != devSD11+"\r\n" {
		t.Fatalf("%q", b)
	}
	ms, errs := decodeBytes(newCodec(t, ""), z)
	if len(errs) != 0 || len(ms) != 1 || ms[0].Records[0].Fix == nil {
		t.Fatalf("%v %v", ms, errs)
	}
}
