// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package gt06_test

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"math"
	"testing"
	"time"

	"github.com/cB-Sigma/trackers/gt06"
	"github.com/cB-Sigma/trackers/track"
)

// Frames of the further protocol numbers. Device frames quoted in Traccar's
// GT06 tests (Apache-2.0, see NOTICE) and the Concox GK310 protocol
// document's examples, used as facts.
const (
	vGPS10      = "787819100B031A0B1B31CC027AC7FD0C4657BF0115210001001CC6070D0A"
	vHeart23    = "78780B23C00122040001000818720D0A"
	vLBSAlarm19 = "78781219028f0a29e10036f12003040102000875dc0d0a"
	vLBSAlarmA5 = "787819a5012ed0000075df000000000098661502050413000019a12b0d0a"
	vFences27   = "78782627100419092D07C5027AC91C0C4658000005370900000000000000008002001900FF00004DF60D0A"
	vFencesA4   = "78782da41a0509160203cf05be31f80c306530001c0010012ed000007ef40000000006428b074205041302ff0009389c0d0a"
	vFencesA4b  = "78782EA4110C0C02281BF6026C18720C38D22800149C1181CC00010000260E000000000615F8012C05041102FF001058FD0D0A"
	vAddr2A     = "78782E2A0F0C1D071139CA027AC8000C4658000014D83132353230313335333231373730373900000000000001002A6ECE0D0A"
	vAddr17     = "78782417 01CC00287D001F71 3132353230313335333231373730373900000000000001002A7DD60D0A"
	v4GLocA0    = "787829a01707150f2d0ecd01635100041e96d000087c02d4020000912e000000000718798d000e0006ed3ce50d0a"
	v4GLocA0b   = "78782aa015041007350eca027ac8a20c4658be00140081cc00000000287d0000000002ea5e010004000009dffc0d0a"
	v4GLBSA1    = "78786CA1110B0413093801CC01000025FC000000000618C10201000025FC000000000618C10201000025FC000000000618C10201000025FC000000000618C10201000025FC000000000618C10201000025FC000000000618C10201000025FC000000000618C10201FF0002000541D70D0A"
	v4GWiFiA2   = "78787aa2110c0e06372c813601040000591200000000009d7c01040000591200000000009d7c01040000591200000000009d7c01040000591200000000009d7c01040000591200000000009d7c01040000591200000000009d7c01040000591200000000009d7c0104ff02001801eb4039d10000000000000004fabeb50d0a"
	v4GWiFiA2lw = "787840a2180b0f0f3407cf00602cd208354064001c6a02dc650000698100000000095674c9114100002a04000100004b31000000000863829079286793020001a22a8f0d0a"
	vTransp9B   = "797900109b0344373532304136320d0a000f87f00d0a"
	vTransp9Bb  = "797900099b0380d600046f91e90d0a"
	vExt32      = "7979004a321106170c1b180cc900a875580b7ab4f00010350901fe0a007c0009112424007c000912240081004efe2100c500100f1200000000000000000000000000000000000000000000bc7c900d0a"
	vExt32wifi  = "7979007632110706090217000901fe0a060f006a1c2024060f0053a429060f006a1d21060f0053a720060f006f151d0000000000000000000000003844d9e7f7e1773d60e327a9e442405cf28628b9c640a42bb0fc0d0244d855a38c220a4c802aa8da7dab50b0e235ef32dd5348ee0ce77a52540000010a205a0d0a"
	vExt33      = "797900143311070609020b00000000a0030046000109e4610d0a"
)

func near(a, b float64) bool { return math.Abs(a-b) < 1e-5 }

func alertTypes(r track.Record) []string {
	var s []string
	for _, a := range r.Alerts {
		s = append(s, a.Type)
	}
	return s
}

func TestFurtherProtocolNumbers(t *testing.T) {
	ms := decodeAll(t, "", vLogin, vGPS10, vHeart23, vLBSAlarm19, vLBSAlarmA5, vFences27, vFencesA4, vFencesA4b, vAddr2A, vAddr17)
	if len(ms) != 10 {
		t.Fatalf("decoded %d frames", len(ms))
	}
	for i, m := range ms {
		if m == nil && i != 5 {
			t.Fatalf("frame %d skipped", i)
		}
	}

	// 0x10: a GPS block only, not answered by default.
	f := ms[1].Records[0].Fix
	if f == nil || f.Time != time.Date(2011, 3, 26, 11, 27, 49, 0, time.UTC) || !f.Valid || *f.Heading != 0x121 || *f.Speed != 1 ||
		!near(f.Lat, float64(0x027AC7FD)/1800000) || ms[1].Reply != nil {
		t.Fatalf("0x10 %+v reply % X", f, ms[1].Reply)
	}

	// 0x23: terminal information, voltage in hundredths of a volt; answered.
	r := ms[2].Records[0]
	if r.Status["batteryVoltage"] != 2.90 || r.Status["gsm"] != 4 || r.Status["fuelCut"] != true || r.Status["ignition"] != false ||
		!bytes.Equal(ms[2].Reply, gt06.Encode(gt06.PHeartbeat, nil, 0x0008)) {
		t.Fatalf("0x23 %+v reply % X", r, ms[2].Reply)
	}

	// 0x19: one cell, status and alarm 0x01 (SOS); answered.
	r = ms[3].Records[0]
	if c := r.Network.Cells[0]; c.MCC != 655 || c.MNC != 10 || c.LAC != 0x29E1 || c.CID != 0x36F1 || r.Fix != nil {
		t.Fatalf("0x19 %+v", r.Network)
	}
	if a := alertTypes(r); len(a) != 1 || a[0] != "emergency" || r.Status["batteryLevel"] != 3 || ms[3].Reply == nil {
		t.Fatalf("0x19 %v %v", a, r.Status)
	}

	// 0xA5: the 4G cell (LAC 4 bytes, cell ID 8 bytes), alarm 0x13 tamper.
	r = ms[4].Records[0]
	if c := r.Network.Cells[0]; c.MCC != 302 || c.MNC != 208 || c.LAC != 0x75DF || c.CID != 0x986615 {
		t.Fatalf("0xA5 %+v", r.Network.Cells)
	}
	if a := alertTypes(r); len(a) != 1 || a[0] != "tamper" || r.Status["ignition"] != true {
		t.Fatalf("0xA5 %v %v", a, r.Status)
	}

	// 0x27: as 0x26 with a fence number; alarm 0x19 (internal battery low).
	// The quoted frame's CRC does not match: strict, it is passed over.
	if ms[5] != nil {
		t.Fatal("0x27 with a bad CRC was taken")
	}
	ms[5] = decodeAll(t, `{"checkCrc": false}`, vLogin, vFences27)[1]
	r = ms[5].Records[0]
	if a := alertTypes(r); len(a) != 1 || a[0] != "low-battery" || r.Status["geofenceId"] != 0xFF || r.Fix == nil || r.Network != nil {
		t.Fatalf("0x27 %v %+v", a, r)
	}

	// 0xA4: the LBS block's length says it holds a 4G cell.
	r = ms[6].Records[0]
	if c := r.Network.Cells[0]; c.MCC != 302 || c.MNC != 208 || c.LAC != 0x7EF4 || c.CID != 0x06428B07 {
		t.Fatalf("0xA4 %+v", r.Network.Cells)
	}
	if a := alertTypes(r); len(a) != 1 || a[0] != "tamper" || r.Status["gsm"] != 4 || ms[6].Reply == nil {
		t.Fatalf("0xA4 %v", a)
	}
	// ... and a two-byte MNC when the MCC's top bit is set.
	r = ms[7].Records[0]
	if c := r.Network.Cells[0]; c.MCC != 460 || c.MNC != 1 || c.LAC != 0x260E || c.CID != 0x0615F801 {
		t.Fatalf("0xA4 b %+v", r.Network.Cells)
	}
	if a := alertTypes(r); len(a) != 1 || a[0] != "power-off" {
		t.Fatalf("0xA4 b %v", a)
	}

	// 0x2A: an address request with a position and a phone number; not
	// answered (the address is the server's to look up: AddressReply).
	r = ms[8].Records[0]
	if r.Fix == nil || r.Status["addressRequest"] != true || r.Status["phone"] != "1252013532177079" || ms[8].Reply != nil {
		t.Fatalf("0x2A %+v reply % X", r, ms[8].Reply)
	}
	// 0x17 in a normal frame (not the WiFi count-in-header frame): an
	// address request with a cell.
	r = ms[9].Records[0]
	if r.Status["phone"] != "1252013532177079" || r.Network.Cells[0].LAC != 0x287D || r.Network.Cells[0].CID != 0x1F71 {
		t.Fatalf("0x17 %+v", r)
	}
}

func TestFourGLocationAndCells(t *testing.T) {
	ms := decodeAll(t, "", vLogin, v4GLocA0, v4GLocA0b, v4GLBSA1, v4GWiFiA2, v4GWiFiA2lw, vStatus)
	if len(ms) != 7 {
		t.Fatalf("decoded %d frames", len(ms))
	}
	// 0xA0: GPS, a 4G cell, ACC, upload mode, re-upload.
	r := ms[1].Records[0]
	if r.Fix == nil || r.Fix.Valid || r.Fix.Time != time.Date(2023, 7, 21, 15, 45, 14, 0, time.UTC) || r.Fix.Lat >= 0 || r.Fix.Lon >= 0 {
		t.Fatalf("0xA0 %+v", r.Fix)
	}
	if c := r.Network.Cells[0]; c.MCC != 724 || c.MNC != 2 || c.LAC != 0x912E || c.CID != 0x0718798D || r.Status["ignition"] != false ||
		r.Status["uploadMode"] != 0x0E || r.History || ms[1].Reply != nil {
		t.Fatalf("0xA0 %+v %v", r.Network.Cells, r.Status)
	}
	r = ms[2].Records[0]
	if c := r.Network.Cells[0]; c.MCC != 460 || c.MNC != 0 || c.LAC != 0x287D || c.CID != 0x02EA5E01 || !r.Fix.Valid {
		t.Fatalf("0xA0 b %+v", r.Network.Cells)
	}
	// 0xA1: seven 4G cells, timing advance unknown; answered.
	n := ms[3].Records[0].Network
	if len(n.Cells) != 7 || n.Cells[0].MCC != 460 || n.Cells[0].MNC != 1 || n.Cells[0].LAC != 0x25FC || n.Cells[0].CID != 0x0618C102 || n.TA != nil {
		t.Fatalf("0xA1 %+v", n)
	}
	if !bytes.Equal(ms[3].Reply, gt06.Encode(gt06.P4GLBSMulti, nil, 0x0005)) {
		t.Fatalf("0xA1 reply % X", ms[3].Reply)
	}
	// 0xA2: 4G cells and access points (two-byte MNC); empty MACs dropped.
	n = ms[4].Records[0].Network
	if len(n.Cells) != 7 || n.Cells[0].MCC != 310 || n.Cells[0].MNC != 260 || len(n.WiFi) != 1 || n.WiFi[0].MAC != "00:18:01:eb:40:39" {
		t.Fatalf("0xA2 %+v", n)
	}
	// A 0xA2 frame of another layout is passed over, the stream stays in step.
	if ms[5] != nil || ms[6] == nil {
		t.Fatalf("0xA2 other layout %v %v", ms[5], ms[6])
	}
}

func TestTransparentAndExtendedFrames(t *testing.T) {
	ms := decodeAll(t, "", vLogin, vTransp9B, vTransp9Bb, vExt32, vExt32wifi, vExt33)
	if len(ms) != 6 {
		t.Fatalf("decoded %d frames", len(ms))
	}
	for i, m := range ms {
		if m == nil {
			t.Fatalf("frame %d skipped", i)
		}
	}
	if st := ms[1].Records[0].Status; st["externalDevice"] != 3 || st["externalData"] != "D7520A62" || ms[1].Reply != nil {
		t.Fatalf("0x9B %v", st)
	}
	if st := ms[2].Records[0].Status; st["externalData"] != "80D600" {
		t.Fatalf("0x9B binary %v", st)
	}
	// 0x32 in a 0x7979 frame: GPS and cell blocks with their own lengths.
	r := ms[3].Records[0]
	if r.Fix == nil || !r.Fix.Valid || r.Fix.Time != time.Date(2017, 6, 23, 12, 27, 24, 0, time.UTC) || len(r.Network.Cells) < 2 ||
		r.Network.Cells[0].MCC != 510 || r.Network.Cells[0].MNC != 10 || r.Network.Cells[0].LAC != 0x7C || r.Network.Cells[0].CID != 0x911 {
		t.Fatalf("0x32 %+v %+v", r.Fix, r.Network)
	}
	if !bytes.Equal(ms[3].Reply[:2], []byte{0x79, 0x79}) || ms[3].Reply[4] != 0x32 {
		t.Fatalf("0x32 reply % X", ms[3].Reply)
	}
	// Without a fix: the cells and eight access points.
	r = ms[4].Records[0]
	if r.Fix != nil || len(r.Network.Cells) != 5 || len(r.Network.WiFi) != 8 || r.Network.WiFi[0].MAC != "44:d9:e7:f7:e1:77" {
		t.Fatalf("0x32 wifi %+v", r.Network)
	}
	// 0x33: status 0xA0 is armed.
	if st := ms[5].Records[0].Status; st["armed"] != true {
		t.Fatalf("0x33 %v", st)
	}
	// 0x32 in a 0x7878 frame is another device's layout: passed over.
	ms = decodeAll(t, "", vLogin, "7878293218061301261ccd0274c4ad050d7c960018000a02d4000ac3c70dbdc40b46f004210202af001784290d0a")
	if len(ms) != 2 || ms[1] != nil {
		t.Fatalf("0x7878 0x32 %v", ms)
	}
}

func TestAddressReplyFrame(t *testing.T) {
	b := gt06.AddressReply(1, "MG Road, Bengaluru", "1252013532177079", 5)
	f, err := gt06.ReadServerFrame(bufioReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if !f.Ext || f.Protocol != gt06.PAddressReply || f.Serial != 5 {
		t.Fatalf("%+v", f)
	}
	c := f.Content
	if int(c[0])<<8|int(c[1]) != len(c)-2 || !bytes.Equal(c[2:6], []byte{0, 0, 0, 1}) || !bytes.HasPrefix(c[6:], []byte("ADDRESS&&\x00M\x00G")) ||
		!bytes.HasSuffix(c, []byte("&&1252013532177079\x00\x00\x00\x00\x00##")) {
		t.Fatalf("% X", c)
	}
}

func TestMoreAlarmCodes(t *testing.T) {
	login := gt06.Encode(gt06.PLogin, h("0123456789012345"), 1)
	alarm := func(code byte) []byte {
		c := append(h(vAlarm)[4:22:22], 0x09, 0x01, 0x94, 0x00, 0x28, 0x7D, 0x00, 0x1F, 0x71, 0x02, 0x04, 0x04, code, 0x02)
		return gt06.Encode(gt06.PAlarm, c, 2)
	}
	for code, want := range map[byte]string{0x14: "door-open", 0x0E: "low-battery", 0xFE: "ignition-on", 0xFF: "ignition-off", 0x13: "tamper", 0x55: "alarm-0x55"} {
		ms := decodeAll(t, "", hexs(login), hexs(alarm(code)))
		if len(ms) != 2 || ms[1] == nil {
			t.Fatalf("0x%02X: %v", code, ms)
		}
		if a := alertTypes(ms[1].Records[0]); len(a) != 1 || a[0] != want {
			t.Errorf("0x%02X: %v, want %s", code, a, want)
		}
	}
	// A profile still overrides a default.
	ms := decodeAll(t, `{"alarms": {"0x14": "box-opened"}}`, hexs(login), hexs(alarm(0x14)))
	if a := alertTypes(ms[1].Records[0]); len(a) != 1 || a[0] != "box-opened" {
		t.Errorf("profile: %v", a)
	}
}

func bufioReader(b []byte) *bufio.Reader { return bufio.NewReader(bytes.NewReader(b)) }

func hexs(b []byte) string { return hex.EncodeToString(b) }
