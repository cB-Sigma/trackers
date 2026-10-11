package gt06_test

import (
	"bytes"
	"testing"
	"time"

	"github.com/cB-Sigma/trackers/gt06"
)

// Cell and WiFi frames quoted in Traccar's GT06 tests (Apache-2.0, see
// NOTICE), used as facts.
const (
	vLBS28   = "78783b2810010d02020201cc00287d001f713e287d001f7231287d001e232d287d001f4018000000000000000000000000000000000000ff00020005b14b0d0a"
	vLBS18   = "78783b18100c0f1201010195271784005ab63617840002fa47178400ff8f4817840019f3491784005ab54b178400ff8e4c17840019f24cff0002012287c80d0a"
	vLBSWiFi = "7878412c11030b011c1f013604cb8a00b17754cb8a00bef357cb8a00b73f5fcb8900b0e25fcb8900b6655fcb8a00b74960cb8a00b178620701001801eb40393800bbbde10d0a"
	vWiFi69  = "787803691604130318491475905bd30e25001e10bbf7635d14759006e626560501cc0028660f213228660f1f2828660ea81e286610731428660f20140d0a"
	vWiFi69z = "7878006919012105090303028f01007549e05a00bc9c5c5a007a8d1a5a0d0a"
	vWiFi17  = "787808171709281135331491827b75594dc8d719a9708452cad719a9708550cad719a97086521491827b75574cac9e17b308085dc8d71939633947cad71939633a480700cc0400d37a3d5a00d37a3d5a00d37a3d5a00d37a3d5a00d37a3d5a00d37a3d5a00d37a3d5a0d0a"
)

// Covers: SIG-IPE-808
func TestLBSAndWiFiPublishedFrames(t *testing.T) {
	ms := decodeAll(t, "", vLBS28, vLBS18, vLBSWiFi, vWiFi69, vWiFi69z, vWiFi17, vStatus)
	if len(ms) != 7 {
		t.Fatalf("decoded %d frames", len(ms))
	}
	for i, m := range ms {
		if m == nil {
			t.Fatalf("frame %d skipped (CRC or layout)", i)
		}
	}
	// 0x28: MCC 460, MNC 0, four cells, timing advance unknown; answered.
	r := ms[0].Records[0]
	n := r.Network
	if r.Time != time.Date(2016, 1, 13, 2, 2, 2, 0, time.UTC) || len(n.Cells) != 4 || n.TA != nil || len(n.WiFi) != 0 {
		t.Fatalf("0x28 %+v %+v", r, n)
	}
	if c := n.Cells[0]; c.MCC != 460 || c.MNC != 0 || c.LAC != 0x287D || c.CID != 0x1F71 || *c.RSSI != -0x3E {
		t.Fatalf("0x28 cell %+v", c)
	}
	if !bytes.Equal(ms[0].Reply, gt06.Encode(gt06.PLBSMulti, nil, 0x0005)) {
		t.Fatalf("0x28 reply % X", ms[0].Reply)
	}
	// 0x18: MCC 405, MNC 39, seven cells.
	n = ms[1].Records[0].Network
	if len(n.Cells) != 7 || n.Cells[0].MCC != 405 || n.Cells[0].MNC != 39 || n.Cells[0].CID != 0x5AB6 || *n.Cells[6].RSSI != -0x4C {
		t.Fatalf("0x18 %+v", n)
	}
	if ms[1].Reply == nil {
		t.Fatal("0x18 not answered")
	}
	// 0x2C: seven cells, TA 7, one access point.
	n = ms[2].Records[0].Network
	if len(n.Cells) != 7 || n.Cells[0].MCC != 310 || n.Cells[0].MNC != 4 || *n.TA != 7 || len(n.WiFi) != 1 ||
		n.WiFi[0].MAC != "00:18:01:eb:40:39" || *n.WiFi[0].RSSI != -0x38 {
		t.Fatalf("0x2C %+v", n)
	}
	if !bytes.Equal(ms[2].Reply, gt06.Encode(gt06.PLBSWiFi, nil, 0x00BB)) {
		t.Fatalf("0x2C reply % X", ms[2].Reply)
	}
	// 0x69: three access points (count in the header), BCD time, five
	// cells; answered with the time.
	r = ms[3].Records[0]
	n = r.Network
	if r.Time != time.Date(2016, 4, 13, 3, 18, 49, 0, time.UTC) || len(n.WiFi) != 3 || n.WiFi[0].MAC != "14:75:90:5b:d3:0e" ||
		*n.WiFi[0].RSSI != -0x25 || len(n.Cells) != 5 || n.Cells[0].MCC != 460 || n.Cells[0].LAC != 0x2866 || n.Cells[0].CID != 0x0F21 || n.Cells[0].RSSI != nil {
		t.Fatalf("0x69 %+v %+v", r, n)
	}
	if want := h("7878006916041303184 90d0a"); !bytes.Equal(ms[3].Reply, want) {
		t.Fatalf("0x69 reply % X", ms[3].Reply)
	}
	if n = ms[4].Records[0].Network; len(n.WiFi) != 0 || len(n.Cells) != 3 || n.Cells[0].MCC != 655 || n.Cells[0].MNC != 1 {
		t.Fatalf("0x69 without access points %+v", n)
	}
	if n = ms[5].Records[0].Network; len(n.WiFi) != 8 || len(n.Cells) != 7 || n.Cells[0].MCC != 204 || n.Cells[0].MNC != 4 {
		t.Fatalf("0x17 %+v", n)
	}
	// Framing stays in step after the count-in-header frames.
	if ms[6].Records[0].Status["gsm"] != 4 {
		t.Fatalf("status after WiFi frames %+v", ms[6].Records[0])
	}
	// An LBS frame shorter than the standard layout is skipped, not fatal.
	short := gt06.Encode(gt06.PLBSMulti3, h("100101020202 01cc00 287d001f713e"), 9)
	if ms := decodeAll(t, "", string(hexOf(short)), vStatus); len(ms) != 2 || ms[0] != nil || ms[1] == nil {
		t.Fatalf("short LBS %v", ms)
	}
}

func hexOf(b []byte) []byte {
	const digits = "0123456789abcdef"
	out := make([]byte, 0, 2*len(b))
	for _, v := range b {
		out = append(out, digits[v>>4], digits[v&0x0F])
	}
	return out
}
