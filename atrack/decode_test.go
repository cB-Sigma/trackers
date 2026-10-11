// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package atrack_test

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

	"github.com/cB-Sigma/trackers/atrack"
	"github.com/cB-Sigma/trackers/track"
)

// Device packets below are from Traccar's AtrackProtocolDecoderTest and
// AtrackFrameDecoderTest (Apache-2.0), used as test vectors only.

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func codec(t *testing.T, profile string) track.Codec {
	t.Helper()
	nc, err := atrack.NewCodec(json.RawMessage(profile))
	if err != nil {
		t.Fatal(err)
	}
	return nc()
}

func decodeAll(t *testing.T, c track.Codec, in []byte) []*track.Message {
	t.Helper()
	r := bufio.NewReader(bytes.NewReader(in))
	var out []*track.Message
	for {
		m, err := c.Decode(r)
		if err != nil {
			if errors.Is(err, track.ErrSkip) {
				continue
			}
			if errors.Is(err, io.EOF) {
				return out
			}
			t.Fatalf("decode: %v", err)
		}
		out = append(out, m)
	}
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-6 }

// A binary position: header, CRC-16/ARC from the length on, the unit ID
// as IMEI, one record with its fix and status, and the 0xFE02 answer
// carrying unit ID and sequence.
func TestBinaryPosition(t *testing.T) {
	c := codec(t, "")
	ms := decodeAll(t, c, unhex(t, "40501e58003301e000014104d8f19682525ecd5d525ee344525ee35effc88815026ab4d70000020000104403de01000b0000000007d007d000"))
	if len(ms) != 1 {
		t.Fatalf("%d messages", len(ms))
	}
	m := ms[0]
	if m.IMEI != "352964052096642" || !m.Login || m.Kind != "position" || len(m.Records) != 1 {
		t.Fatalf("%+v", m)
	}
	if hex.EncodeToString(m.Reply) != "fe0200014104d8f1968201e0" {
		t.Fatalf("reply %x", m.Reply)
	}
	r := m.Records[0]
	f := r.Fix
	if f == nil || !f.Valid || !f.Time.Equal(time.Date(2013, 10, 16, 17, 31, 9, 0, time.UTC)) ||
		!near(f.Lat, 40.547543) || !near(f.Lon, -3.635179) || *f.Speed != 11 || *f.Heading != 0 || *f.HDOP != 99 {
		t.Fatalf("fix %+v", f)
	}
	if r.Status["event"] != 2 || r.Status["odometer"] != 416.4 || r.Status["inputs"] != 1 || r.Status["outputs"] != 0 {
		t.Fatalf("status %v", r.Status)
	}
	if _, ok := r.Status["temp1"]; ok {
		t.Fatal("a disconnected sensor (2000) was reported")
	}
}

// Two records in one packet; trailing padding shorter than a record is
// passed over.
func TestBinaryRecordsAndPadding(t *testing.T) {
	c := codec(t, "")
	ms := decodeAll(t, c, unhex(t, "4050993f005c000200014104d8f19682525666c252568c3c52568c63ffc8338402698885000002000009cf03de0100000000000007d007d000525666c252568c5a52568c63ffc8338402698885000002000009cf03de0100000000000007d007d000"))
	if len(ms) != 1 || len(ms[0].Records) != 2 {
		t.Fatalf("%+v", ms)
	}
	c = codec(t, `{"checkCrc": false}`)
	ms = decodeAll(t, c, unhex(t, "40501e58003301e000014104d8f19682525ecd5d525ee344525ee35effc88815026ab4d70000020000104403de01000b0000000007d007d000000000000000"))
	if len(ms) != 1 || len(ms[0].Records) != 1 {
		t.Fatalf("%+v", ms)
	}
}

// A zero time and position is an invalid fix.
func TestBinaryNoFix(t *testing.T) {
	c := codec(t, "")
	ms := decodeAll(t, c, unhex(t, "40503835003300070001441c3d8ed1c400000000000000c9000000c900000000000000000000020000000003de0100000000000007d007d000"))
	if len(ms) != 1 || ms[0].IMEI != "356363059253700" || len(ms[0].Records) != 1 || ms[0].Records[0].Fix.Valid {
		t.Fatalf("%+v", ms)
	}
}

// The keep-alive is answered with itself.
func TestKeepAlive(t *testing.T) {
	c := codec(t, "")
	ms := decodeAll(t, c, unhex(t, "fe0200014104d8f196820001"))
	if len(ms) != 1 || ms[0].IMEI != "352964052096642" || ms[0].Kind != "keepalive" || hex.EncodeToString(ms[0].Reply) != "fe0200014104d8f196820001" {
		t.Fatalf("%+v", ms)
	}
}

// Binary records carrying their custom-information layout (%CI): main
// and backup voltage and motion decode on each of 13 records.
func TestBinaryCustomInfo(t *testing.T) {
	c := codec(t, `{"checkCrc": false}`)
	ms := decodeAll(t, c, unhex(t, "405064e503092d8600000000000f54ab660786b0660786b0660a12c4fa2e202d01cfd32a005a02000022b700070000000000000007d007d000254349254d56254256254d5400007f002800660786ec660786ec660a12c4fa2e202d01cfd32a005a02000022b700070000000000000007d007d000254349254d56254256254d5400007f0028006607872866078728660a12c4fa2e202d01cfd32a005a02000022b700070000000000000007d007d000254349254d56254256254d5400007f0028006607876466078764660a12c4fa2e202d01cfd32a005a02000022b700070000000000000007d007d000254349254d56254256254d5400007f002800660787a0660787a0660a12c4fa2e202d01cfd32a005a02000022b700060000000000000007d007d000254349254d56254256254d5400007f002800660787dc660787dc660a12c4fa2e202d01cfd32a005a02000022b700060000000000000007d007d000254349254d56254256254d5400007f0028006607881866078818660a12c4fa2e202d01cfd32a005a02000022b700060000000000000007d007d000254349254d56254256254d5400007f0028006607885466078854660a12c4fa2e202d01cfd32a005a02000022b700060000000000000007d007d000254349254d56254256254d5400007f0028006607889066078890660a12c4fa2e202d01cfd32a005a02000022b700060000000000000007d007d000254349254d56254256254d5400007f002800660788cc660788cc660a12c4fa2e202d01cfd32a005a02000022b700060000000000000007d007d000254349254d56254256254d5400007f0028006607890866078908660a12c4fa2e202d01cfd32a005a02000022b700070000000000000007d007d000254349254d56254256254d5400007f0028006607894466078944660a12c4fa2e202d01cfd32a005a02000022b700070000000000000007d007d000254349254d56254256254d5400007f0028006607898066078980660a12c4fa2e202d01cfd32a005a02000022b700070000000000000007d007d000254349254d56254256254d5400007f002800"))
	if len(ms) != 1 || len(ms[0].Records) != 13 {
		t.Fatalf("%d messages", len(ms))
	}
	st := ms[0].Records[0].Status
	if st["externalVoltage"] != 12.7 || st["batteryVoltage"] != 4.0 || st["movement"] != false {
		t.Fatalf("status %v", st)
	}
}

// A binary record with a long custom layout: cell, ICCID, VIN, IMSI and
// strings between fixed-size fields stay in step.
func TestBinaryLongCustomInfo(t *testing.T) {
	c := codec(t, `{"checkCrc": false}`)
	ms := decodeAll(t, c, unhex(t, "405ad77c01670410000144a77a21281d5b74d2335b74d2335b74d233fabaf3bc02a38d3d010c0200030f8e000701001a0000000007d007d00025434925434525434e25475125475325464c254d4c25564e25504425464325454c254554254344254154254d46254d5625425625434d25445425474c25474e254756254c43254d4525524c25525025534125534d255452254941254d5000000000000004bbf41c0900003254314b523332453238433730363138350000000000004800543839303132363038383132313532343737353900000000ec06a50089002900011a2e3da1882700687474703a2f2f6d6170732e676f6f676c652e636f6d2f6d6170733f713d34342e3237323935372c2d38382e34313132303120000075ff4903fb006fff63040a004dff5d04080030ffa10407003b001304060026000503f9001e002504020078ff6204000073ff7d03f9007aff6903f3ffc0001804040000000144a77a21281d00073f0c001a182400"))
	if len(ms) != 1 || len(ms[0].Records) != 1 {
		t.Fatalf("%+v", ms)
	}
	r := ms[0].Records[0]
	if r.Status["vin"] != "2T1KR32E28C706185" || r.Status["iccid"] != "8901260881215247759" || r.Fix.Sats == nil || *r.Fix.Sats != 12 {
		t.Fatalf("status %v fix %+v", r.Status, r.Fix)
	}
	// The cell ID is 0: no cell is reported.
	if r.Network != nil || r.Status["imsi"] != "310260881524775" {
		t.Fatalf("network %+v status %v", r.Network, r.Status)
	}
}

// Readable binary times (AT$FORM time format 1) are told from Unix
// times by their year.
func TestBinaryReadableTime(t *testing.T) {
	c := codec(t, `{"checkCrc": false}`)
	ms := decodeAll(t, c, unhex(t, "0203b494003c00eb00014104d8dd3a3e07de011b0b1f0307de011b0b1f0307de011b0b1f0300307f28030574d30000020000000600160100020000000007d007d000"))
	if len(ms) != 1 || len(ms[0].Records) != 1 {
		t.Fatalf("%+v", ms)
	}
	if f := ms[0].Records[0].Fix; !f.Time.Equal(time.Date(2014, 1, 27, 11, 31, 3, 0, time.UTC)) || *f.Speed != 2 {
		t.Fatalf("fix %+v", f)
	}
}

// ASCII positions: framed by their length, CRC over the comma before the
// length to the end, readable and Unix times, the text message and the
// custom layout the record names.
func TestASCIIPositions(t *testing.T) {
	c := codec(t, "")
	in := "@P,75B3,120,79779,358901048091554,20180412142514,20180412142514,20180413000655,16423389,48178700,108,2,6.5,9,0,0,0,0,0,2000,2000,\x1a\r\n" +
		"@P,872D,712,65221,357298070426498,1534715862,1534715862,1534726474,-88510995,44260676,176,2,56827,6,1,0,0,0,,2000,2000,\x1a,%CI%GQ%GS%CN%CE%MV%SA,29,10,310260,7888674,144,16\r\n" +
		"1534715921,1534715922,1534726474,-88511023,44260668,176,2,56827,6,1,0,0,0,,2000,2000,\x1a,%CI%GQ%GS%CN%CE%MV%SA,28,10,310260,7888674,144,16\r\n" +
		"1534715982,1534715982,1534726474,-88511046,44260668,176,2,56827,6,1,0,0,0,,2000,2000,\x1a,%CI%GQ%GS%CN%CE%MV%SA,29,9,310260,7888674,144,16\r\n" +
		"1534716041,1534716042,1534726474,-88511011,44260663,176,2,56827,6,1,0,0,0,,2000,2000,\x1a,%CI%GQ%GS%CN%CE%MV%SA,29,10,310260,7888674,144,16\r\n" +
		"1534716102,1534716102,1534726474,-88510988,44260676,176,2,56827,6,1,0,0,0,,2000,2000,\x1a,%CI%GQ%GS%CN%CE%MV%SA,29,10,310260,7888674,145,16\r\n" +
		"@P,7A66,153,9022,863003048505515,20210207000103,20210207000103,20210207000103,103939276,1348903,97,2,5628,8,0,0,0,0,,2000,2000,\x1a,%CI%BC,3:224:F128833445E6002C09C6\r\n"
	ms := decodeAll(t, c, []byte(in))
	if len(ms) != 3 {
		t.Fatalf("%d messages", len(ms))
	}
	m := ms[0]
	// The sequence 79779 does not fit the answer's 16 bits: 79779 mod 65536.
	if m.IMEI != "358901048091554" || len(m.Records) != 1 || hex.EncodeToString(m.Reply) != "fe020001466b297b23a237a3" {
		t.Fatalf("%+v %x", m, m.Reply)
	}
	f := m.Records[0].Fix
	if !f.Time.Equal(time.Date(2018, 4, 12, 14, 25, 14, 0, time.UTC)) || !near(f.Lon, 16.423389) || !near(f.Lat, 48.1787) || *f.Heading != 108 {
		t.Fatalf("fix %+v", f)
	}
	// This device's ASCII CRC does not follow the document's rule: the
	// packet is read, with a warning.
	if len(m.Warnings) != 1 || m.Warnings[0].Code != "crcMismatch" {
		t.Fatalf("warnings %+v", m.Warnings)
	}
	if len(ms[2].Warnings) != 0 {
		t.Fatalf("warnings %+v", ms[2].Warnings)
	}
	m = ms[1]
	if m.IMEI != "357298070426498" || len(m.Records) != 5 {
		t.Fatalf("%+v", m)
	}
	r := m.Records[0]
	if !r.Fix.Time.Equal(time.Unix(1534715862, 0)) || !near(r.Fix.Lon, -88.510995) || r.Status["externalVoltage"] != 14.4 || *r.Fix.Sats != 16 {
		t.Fatalf("record %+v %v", r.Fix, r.Status)
	}
	if r.Network == nil || r.Network.Cells[0].CID != 7888674 || r.Network.Cells[0].MCC != 310 || r.Network.Cells[0].MNC != 260 {
		t.Fatalf("network %+v", r.Network)
	}
	if ms[2].IMEI != "863003048505515" || len(ms[2].Records) != 1 {
		t.Fatalf("%+v", ms[2])
	}
}

// A bad CRC is passed over with a warning naming profile.checkCrc.
func TestCRCMismatch(t *testing.T) {
	c := codec(t, "")
	b := unhex(t, "40501e58003301e000014104d8f19682525ecd5d525ee344525ee35effc88815026ab4d70000020000104403de01000b0000000007d007d000")
	b[3] ^= 1
	_, err := c.Decode(bufio.NewReader(bytes.NewReader(b)))
	var sk *track.Skip
	if !errors.As(err, &sk) || sk.Code != "crcMismatch" || sk.Setting != "profile.checkCrc" {
		t.Fatalf("%v", err)
	}
}

// Command answers: $OK, $ERROR with its code, $INFO with the device's
// details, each with the tag it was sent with as correlation.
func TestAnswers(t *testing.T) {
	c := codec(t, "")
	ms := decodeAll(t, c, []byte("$OK\r\n$OK+12\r\n$ERROR+7=102\r\n$INFO=358683066267395,AX7,Rev.0.61 Build.1624,358683066267395,466924131626767,89886920041316267670,144,0,9,1,12,1,0\r\n$TRAC+9=1,30,20,15,0,0,2,0,0,1\r\n"))
	if len(ms) != 5 {
		t.Fatalf("%d", len(ms))
	}
	if ms[0].Response == nil || *ms[0].Response != "OK" || ms[0].Failed || ms[0].Correlation != "" || ms[0].Kind != "response" {
		t.Fatalf("%+v", ms[0])
	}
	if ms[1].Correlation != "12" {
		t.Fatalf("%+v", ms[1])
	}
	if !ms[2].Failed || ms[2].Correlation != "7" || ms[2].Details["error"] != "102" || !strings.Contains(ms[2].Details["reason"].(string), "parameter") {
		t.Fatalf("%+v", ms[2])
	}
	d := ms[3].Details
	if ms[3].Failed || d["model"] != "AX7" || d["firmware"] != "Rev.0.61 Build.1624" || d["iccid"] != "89886920041316267670" || d["externalVoltage"] != 14.4 {
		t.Fatalf("%+v", ms[3])
	}
	if *ms[4].Response != "TRAC=1,30,20,15,0,0,2,0,0,1" || ms[4].Correlation != "9" {
		t.Fatalf("%+v", ms[4])
	}
}

// Report IDs map to alerts through the profile (the user-defined reports
// 101..164 mean what the operator configured); 13 is GSM jamming.
func TestAlarms(t *testing.T) {
	c := codec(t, `{"alarms": {"101": "emergency"}}`)
	rec := atrack.ASCIIFrame("@P", "1,358901048091554,1534715862,1534715862,1534726474,-88510995,44260676,176,101,56827,6,1,0,0,0,,2000,2000,\x1a\r\n")
	rec2 := atrack.ASCIIFrame("@P", "2,358901048091554,1534715862,1534715862,1534726474,-88510995,44260676,176,13,56827,6,1,0,0,0,,2000,2000,\x1a\r\n")
	ms := decodeAll(t, c, []byte(rec+rec2))
	if len(ms) != 2 || len(ms[0].Records[0].Alerts) != 1 || ms[0].Records[0].Alerts[0].Type != "emergency" || ms[0].Records[0].Alerts[0].Severity != track.Critical ||
		ms[1].Records[0].Alerts[0].Type != "gsm-jamming" {
		t.Fatalf("%+v", ms)
	}
	if _, err := atrack.NewCodec(json.RawMessage(`{"alarms": {"x": "emergency"}}`)); err == nil {
		t.Fatal("bad report ID accepted")
	}
}

// A binary packet whose CRC starts with a comma is not taken for ASCII.
func TestBinaryCommaCRC(t *testing.T) {
	rec := unhex(t, "525ecd5d525ee344525ee35effc88815026ab4d70000020000104403de01000b0000000007d007d000")
	for seq := uint16(0); seq < 60000; seq++ {
		b := atrack.BinaryFrame("@P", seq, 352964052096642, rec)
		if b[2] != ',' {
			continue
		}
		ms := decodeAll(t, codec(t, ""), b)
		if len(ms) != 1 || len(ms[0].Records) != 1 {
			t.Fatalf("%x: %+v", b, ms)
		}
		return
	}
	t.Fatal("no sequence gives a comma CRC")
}

// The simulator-facing builders frame what the codec reads.
func TestBuilders(t *testing.T) {
	c := codec(t, "")
	b := atrack.BinaryFrame("@P", 5, 352964052096642, unhex(t, "525ecd5d525ee344525ee35effc88815026ab4d70000020000104403de01000b0000000007d007d000"))
	ms := decodeAll(t, c, b)
	if len(ms) != 1 || len(ms[0].Records) != 1 || hex.EncodeToString(ms[0].Reply) != hex.EncodeToString(atrack.Ack(352964052096642, 5)) {
		t.Fatalf("%+v", ms)
	}
}
