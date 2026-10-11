// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package queclink_test

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/cB-Sigma/trackers/queclink"
	"github.com/cB-Sigma/trackers/track"
)

// Device packets from Traccar's Gl200BinaryProtocolDecoderTest and
// Gl200FrameDecoderTest (Apache-2.0), used as test vectors. The GL300
// (device type 0x45) frames carry the 0x00FC1FBF masks; tcLBC, tcINF and
// tcACK name the device by its device name.
const (
	tcRSP = "2b5253500700fc1fbf005d4501020209563254030003430564377e42071001000000000000007eff75a151025c6a8107e10801081a2a02680003189c1ac500000000000002100700000000000000000007e1080108241019e17ebe0d0a"
	tcLBC = "2B5253500300FC1FFF0064450102020867623130302D446F642F442105007018217345005F010100000001100045073C4D4101DB86BD07E106130B2B0F0460000018770013000000030000000106020F2300002714301107E106130B2B1003424EFB0D0A"
	tcVGN = "2b4556542d00fc1fbf0063450102020956325403000343056437f8220700000200000000010000160100f2007eff75a1f0025c6a1a07e1080108241a02680003189c1ac500000000000002100800000000000000000007e1080108241a19e24e4e0d0a"
	tcPDP = "2b4556540c00fc1fbf005c4501010108563254030003430564312a41090100000000003f007dff75a11a025c6a7807e1070a14041202680003189c1ac500000000000000000000000000000000000007e1070b041134054e5c6e0d0a"
	tcINF = "2b494e4601fd7f0076676231303000000045010202090104020500004100054007e107150b061d0000003f010e02580000000000d0312a1013648935103226313921591f1200000000000302680003189c1ac3001b02680003189c1ac4000d02680003189c1ac5001207e107150b0d3704f658060d0a"
	tcACK = "2b41434b017f244501010108676231303000000000ffff07e1070b03112d054dfe030d0a"
	tcTLV = "2b000038000865134050947226820300030000216a908d67247f5000521619fa8b85e702ab64326a908d670000050082000aa51da13d0424"
	tcLGN = "2b4c474e00ff0026fe110b07020106563454040d054905000007e4031911213905083abd0d0a"
	// The +RESP:GTDOS example of the GV300N @Track Air Interface
	// Protocol V3.01, section 4.5 (one of the examples whose length
	// matches its bytes; it names the device "gv300").
	docDOS = "2B4556541B01FEDFFF0068250206060267763330300000000000000000000000014110010101000000000000000000000000000000000000000000000004600000187708730000000000000000000000000000000000000000000007DB010100021C000D80F60D0A"
	tcIMEI = "865084030003675"
)

func bin(t *testing.T, s ...string) string {
	t.Helper()
	var out []byte
	for _, x := range s {
		b, err := hex.DecodeString(x)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, b...)
	}
	return string(out)
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-6 }

func hasWarning(m *track.Message, code string) bool {
	for _, w := range m.Warnings {
		if w.Code == code {
			return true
		}
	}
	return false
}

func skipCode(err error) string {
	var sk *track.Skip
	if errors.As(err, &sk) {
		return sk.Code
	}
	return ""
}

// Device packets of the HEX format: positions, the items the masks name,
// information reports, acknowledgements and the 0x2B00 record frame.
func TestHexDevicePackets(t *testing.T) {
	ms, skips := decode(t, "", bin(t, tcRSP, tcPDP, tcVGN, tcLBC, tcINF, tcACK, docDOS, tcLGN, tcTLV))
	if len(ms) != 9 || len(skips) != 1 || skipCode(skips[0]) != "unknownMessage" || ms[7] != nil {
		t.Fatalf("decoded %d messages, skips %v", len(ms), skips)
	}
	for i, m := range ms[:7] {
		if m.IMEI != tcIMEI || m.Login != (i == 0) {
			t.Fatalf("message %d: imei %q login %v", i, m.IMEI, m.Login)
		}
	}

	// +RSP GTFRI, GL300 mask 0x00FC1FBF.
	r := ms[0].Records[0]
	f := r.Fix
	if len(ms[0].Records) != 1 || !near(f.Lat, 39.611009) || !near(f.Lon, -9.068207) || *f.Alt != 126 || *f.Sats != 7 || *f.Speed != 0 ||
		f.Valid || f.Time != time.Date(2017, 8, 1, 8, 26, 42, 0, time.UTC) {
		t.Fatalf("GTFRI fix %+v", f)
	}
	if st := r.Status; st["batteryLevel"] != 100 || st["externalVoltage"] != 14.206 || st["odometer"] != 528.7 || st["motionState"] != "sensorMotion" {
		t.Fatalf("GTFRI status %v", st)
	}
	// MCC 0x0268 is MCC 268 (Portugal, where the position is).
	if c := r.Network.Cells[0]; c.MCC != 268 || c.MNC != 3 || c.LAC != 0x189c || c.CID != 0x1ac5 {
		t.Fatalf("GTFRI cell %+v", c)
	}
	if ms[0].Details["report"] != "GTFRI" || len(ms[0].Warnings) != 0 {
		t.Fatalf("GTFRI details %v warnings %v", ms[0].Details, ms[0].Warnings)
	}

	// +EVT GTPDP; then a GL300 event type the GV300N tables do not name:
	// its position is read, with a warning.
	if ms[1].Details["report"] != "GTPDP" || *ms[1].Records[0].Fix.Sats != 9 || ms[1].Records[0].Status["externalVoltage"] != 12.586 {
		t.Fatalf("GTPDP %+v %+v", ms[1].Details, ms[1].Records[0])
	}
	if f := ms[2].Records[0].Fix; !hasWarning(ms[2], "unknownMessage") || *f.Speed != 22.1 || *f.Heading != 242 || !near(f.Lat, 39.610906) {
		t.Fatalf("unnamed event %+v %v", f, ms[2].Warnings)
	}

	// Frames that name the device by name, read as the connection's IMEI.
	r = ms[3].Records[0]
	if ms[3].Details["report"] != "GTLBC" || ms[3].Details["deviceName"] != "gb100-Do" || !r.Fix.Valid || *r.Fix.HDOP != 1 ||
		!near(r.Fix.Lat, 31.164093) || !near(r.Fix.Lon, 121.392449) || r.Status["hourMeter"] != "10004:48:17" || r.Status["ignition"] != true {
		t.Fatalf("GTLBC %+v %v", r.Fix, r.Status)
	}
	st := ms[4].Records[0].Status
	if ms[4].Details["report"] != "GTINF" || st["iccid"] != "8935103226313921591" || st["gsm"] != 18 || st["batteryVoltage"] != 4.115 ||
		st["mainPower"] != true || st["firmware"] != "0209" || len(ms[4].Records[0].Network.Cells) != 3 {
		t.Fatalf("GTINF %v %+v", st, ms[4].Records[0].Network)
	}
	if m := ms[5]; m.Kind != "response" || m.Correlation != "GTSRI/FFFF" || *m.Response != "+ACK:GTSRI,450101,865084030003675,gb100,FFFF,20170711031745,054D$" {
		t.Fatalf("+ACK %q %q", m.Correlation, *m.Response)
	}
	if m := ms[6]; m.Details["report"] != "GTDOS" || m.Records[0].Status["dout1"] != true || m.Records[0].Network.Cells[0].MCC != 460 {
		t.Fatalf("document GTDOS %+v %+v", m.Details, m.Records[0])
	}

	// The 0x2B00 record frame.
	m := ms[8]
	f = m.Records[0].Fix
	if m.IMEI != "865134050947226" || !f.Valid || !near(f.Lat, 44.786738) || !near(f.Lon, -91.519513) || *f.HDOP != 0.5 || *f.Alt != 272.5 || *f.Heading != 130 {
		t.Fatalf("0x2B00 %s %+v", m.IMEI, f)
	}

	// Alone, a frame with only the device name cannot be placed.
	if _, skips := decode(t, "", bin(t, tcACK)); len(skips) != 1 || skipCode(skips[0]) != "messageUnreadable" {
		t.Fatalf("name-only frame: %v", skips)
	}
}

// builder writes HEX frames for the tests (GV300N layouts).
type builder struct{ b []byte }

func (w *builder) put(v ...byte) *builder { w.b = append(w.b, v...); return w }
func (w *builder) u16(v int) *builder     { return w.put(byte(v>>8), byte(v)) }
func (w *builder) u32(v int64) *builder {
	return w.put(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
func (w *builder) when(t time.Time) *builder {
	return w.u16(t.Year()).put(byte(t.Month()), byte(t.Day()), byte(t.Hour()), byte(t.Minute()), byte(t.Second()))
}
func (w *builder) imei(s string) *builder {
	for i := 0; i < 14; i += 2 {
		w.put((s[i]-'0')*10 + s[i+1] - '0')
	}
	return w.put(s[14] - '0')
}

// seal sets the length (at lenAt, size 1 or 2; lenAt 0: none) and adds
// the checksum and the tail.
func (w *builder) seal(lenAt, size int) string {
	n := len(w.b) + 4
	switch size {
	case 1:
		w.b[lenAt] = byte(n)
	case 2:
		binary.BigEndian.PutUint16(w.b[lenAt:], uint16(n))
	}
	w.u16(int(queclink.Crc16(w.b[4:])))
	return string(w.put(0x0D, 0x0A).b)
}

const hexIMEI = "862170010196747"

var at = time.Date(2026, 10, 11, 9, 30, 0, 0, time.UTC)

// report builds a +RSP or +EVT with mask 0x00FEFFBF (or without the
// length bit), analogue input mode bytes when mode, one position.
func report(head string, typ byte, mask uint32, mode bool, extra ...byte) string {
	w := &builder{}
	w.put([]byte(head)...).put(typ).u32(int64(mask))
	lenAt := 0
	if mask&0x80 != 0 {
		lenAt = len(w.b)
		w.u16(0)
	}
	w.put(0x25, 0x03, 0x01, 0x01, 0x02).imei(hexIMEI)
	w.put(87).u16(12600) // battery %, external power mV
	if mode {
		w.u16(0)
	}
	w.u16(3300).u16(0).put(0x03, 0x01, 0x22, 0x18) // analogue 1, 2; inputs, outputs, motion, satellites
	w.put(extra...).put(1)                         // number of positions
	w.put(2).u16(36).put(5).u16(90).u16(900)       // HDOP, speed 36.5, azimuth, altitude
	w.u32(77594600).u32(12971600).when(at)         // longitude, latitude, GPS time
	w.u16(0x0404).u16(0x0045).u16(0x1A2B).u16(0xC3D4).put(0)
	w.u16(1).put(2)                       // current mileage 1.2
	w.u32(1234).put(5)                    // total mileage 1234.5
	w.put(1, 2, 3).u32(10).put(20, 30)    // hour meters
	w.when(at.Add(time.Minute)).u16(0x11) // send time, count
	if lenAt == 0 {
		return w.seal(0, 0)
	}
	return w.seal(lenAt, 2)
}

// HEX frames as the GV300N tables lay them out: heartbeats answered in
// ASCII, reports with the masks' items, the document's variations, frames
// without a length, and ASCII and HEX on one connection.
func TestHexFrames(t *testing.T) {
	hbd := (&builder{}).put('+', 'H', 'B', 'D', 0xEF, 0).put(0x25, 0x03, 0x01, 0x01, 0x02).imei(hexIMEI).when(at).u16(0x11).seal(5, 1)
	sos := report("+RSP", 10, 0x00FEFFBF, true, 0x00, 0x55)    // report ID/type, microphone/speaker
	bsp := report("+BSP", 7, 0x00FEFFBF, true, 0x10)           // a buffered GTFRI
	noMode := report("+EVT", 6, 0x00FEFFBF, false, 0x0D, 0xC5) // GTBPL, 3.525 V, without the mode bytes its bit names
	noLen := report("+EVT", 13, 0x00FEFF3F, true, 0, 0, 0, 60) // GTIGN without a length
	ascii := vHBD
	ms, skips := decode(t, "", hbd+sos+ascii+bsp+noMode+noLen)
	if len(ms) != 6 || len(skips) != 0 {
		t.Fatalf("decoded %d, skips %v", len(ms), skips)
	}
	if m := ms[0]; m.IMEI != hexIMEI || !m.Login || m.Kind != "heartbeat" || string(m.Reply) != "+SACK:GTHBD,250301,0011$" {
		t.Fatalf("+HBD %+v reply %q", m, m.Reply)
	}
	m := ms[1]
	r := m.Records[0]
	if m.Kind != "emergency" || len(r.Alerts) != 1 || r.Alerts[0].Type != "emergency" || r.History {
		t.Fatalf("GTSOS %+v", m)
	}
	f := r.Fix
	if !f.Valid || !near(f.Lat, 12.9716) || !near(f.Lon, 77.5946) || *f.Speed != 36.5 || *f.Heading != 90 || *f.Alt != 900 || *f.HDOP != 2 || *f.Sats != 8 || f.Time != at {
		t.Fatalf("GTSOS fix %+v", f)
	}
	st := r.Status
	if st["batteryLevel"] != 87 || st["externalVoltage"] != 12.6 || st["analog1"] != 3.3 || st["din1"] != true || st["dout1"] != true ||
		st["ignition"] != true || st["motionState"] != "ignitionOnMotion" || st["odometer"] != 1234.5 || st["hourMeter"] != "10:20:30" {
		t.Fatalf("GTSOS status %v", st)
	}
	if c := r.Network.Cells[0]; c.MCC != 404 || c.MNC != 45 || c.LAC != 0x1A2B || c.CID != 0xC3D4 {
		t.Fatalf("cell %+v", c)
	}
	if ms[2].IMEI != docIMEI || ms[2].Kind != "heartbeat" {
		t.Fatalf("ASCII between HEX frames: %+v", ms[2])
	}
	if m := ms[3]; m.Kind != "history" || !m.Records[0].History || m.Details["report"] != "GTFRI" {
		t.Fatalf("+BSP %+v", m)
	}
	if r := ms[4].Records[0]; r.Status["batteryVoltage"] != 3.525 || len(r.Alerts) != 1 || r.Alerts[0].Type != "low-battery" || r.Status["odometer"] != 1234.5 {
		t.Fatalf("GTBPL without mode bytes %+v", r)
	}
	if r := ms[5].Records[0]; ms[5].Details["report"] != "GTIGN" || r.Status["ignition"] != true || r.Alerts[0].Type != "ignition-on" {
		t.Fatalf("GTIGN without a length %+v", r)
	}

	// With profile.sack every HEX report is answered +SACK:<count>$.
	ms, _ = decode(t, `{"sack": true}`, sos)
	if string(ms[0].Reply) != "+SACK:0011$" {
		t.Fatalf("sack %q", ms[0].Reply)
	}
	// A corrupted checksum is read with a warning.
	bad := []byte(sos)
	bad[len(bad)-3] ^= 0xFF
	if ms, _ := decode(t, "", string(bad)); len(ms) != 1 || !hasWarning(ms[0], "crcMismatch") {
		t.Fatalf("checksum mismatch: %+v", ms)
	}
}

// A HEX acknowledgement completes the named command whose serial it
// carries.
func TestHexAcknowledgement(t *testing.T) {
	codec, err := queclink.NewCodecForTest(`{"password": "gv300n"}`, 3)
	if err != nil {
		t.Fatal(err)
	}
	corr, _ := codec.(track.Correlator).Correlation(map[string]any{"action": "locate"}, 1)
	ack := (&builder{}).put('+', 'A', 'C', 'K', 16, 0x6F, 0).put(0x25, 0x03, 0x01, 0x01, 0x02).imei(hexIMEI).
		put(1).u16(4).when(at).u16(0x20).seal(6, 1)
	ms, _ := decode(t, "", ack)
	m := ms[0]
	if corr != "GTRTO/0004" || m.Correlation != corr || m.Details["subCommand"] != "RTL" || m.Kind != "response" ||
		*m.Response != "+ACK:GTRTO,250301,862170010196747,,RTL,0004,20261011093000,0020$" {
		t.Fatalf("ack %q %v %q, want %q", m.Correlation, m.Details, *m.Response, corr)
	}
}
