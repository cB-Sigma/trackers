package meitrack_test

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/trackers/meitrack"
	"github.com/cB-Sigma/trackers/track"
)

const docIMEI = "353358017784062"

// Frames printed in MEITRACK GPRS Protocol V1.8 (sections 3.1, 3.3, 3.17,
// 3.19, 3.21, 3.35, 3.61, 3.63) and the T1 & T333 GPRS Protocol V1.4
// (3.64), byte for byte with the CR LF the documents write as \r\n. Their
// lengths and checksums were checked independently (the sum of every byte
// up to '*', low byte).
const (
	vA10       = "@@Q25,353358017784062,A10*6A\r\n"
	vA10Answer = "$$Q128,353358017784062,AAA,34,22.543176,114.078448,100313093738,A,5,22,2,205,5,-14,0,60,0|0|10133|4110,0000,149|153|173|2707|914,*91\r\n"
	vSOS       = "$$G127,353358017784062,AAA,1,22.538169,114.075958,100313095653,A,3,21,4,46,5,581,0,148,0|0|10133|4172,0000,166|204|205|2709|878,*77\r\n"
	vFenceExit = "$$J132,353358017784062,AAA,21,22.918046,114.089726,080229123812,A,10,22,12,32,1,21,6667,847,0|0|10133|4110,0000,124|181|183|2714|922,*5A\r\n"
	vSpeeding  = "$$k134,353358017784062,AAA,19,22.916675,114.088813,080229123718,A,10,22,61,31,1,21,6635,395,460|0|10133|4110,0000,164|185|181|2712|915,*F7\r\n"
	vHeartbeat = "$$a131,353358017784062,AAA,31,22.913458,114.083183,080229123628,V,9,23,21,83,1,18,1350,127,0|0|10133|4110,0000,169|181|184|2714|919,*60\r\n"
	vA12       = "@@V27,353358017784062,A12,6*D5\r\n"
	vA12Answer = "$$V28,353358017784062,A12,OK*02\r\n"
	vC01       = "@@M34,353358017784062,C01,20,10122*18\r\n"
	vC01Answer = "$$M28,353358017784062,C01,OK*F9\r\n"
	vF00       = "@@j29,353358017784062,F00,1,1*45\r\n"
	vE91Answer = "$$W38,353358017784062,FWV1.00,12345678*1C\r\n"
)

// vCCE is the source data of MEITRACK GPRS (CCE ID) Protocol V1.0 section
// 2.1: a batch of 12 packets, 25 more cached.
const vCCE = "242450313036342C3836313538353034303439343436382C4343452C190000000C0054001500050501060A07001400150209080000091F010A07000B" +
	"260016000017000019A2011A26054023000602D7875701034860CC0604DEBFB5240C806800000DE4A003001C01000000014909040100000000000000" +
	"54001500050501060907001400150209080000091F010A09000B270016000017000019A2011A26054023000602D0875701034160CC0604E8BFB5240C" +
	"806800000DEEA003001C0100000001490904010000000000000054001500050501060907001400150209080000091F010A0B000B2700160000170000" +
	"19A2011A26054023000602CF875701033E60CC0604F2BFB5240C806800000DF8A003001C010000000149090401000000000000005400150005050106" +
	"0A07001400150209080000091F010A08000B270016000017000019A3011A26054023000602D4875701034360CC0604FCBFB5240C806800000D02A103" +
	"001C0100000001490904010000000000000054001500050501060A07001400150209080000091F010A07000B250016000017000019A2011A26054023" +
	"000602DA875701033E60CC060406C0B5240C806800000D0BA103001C0100000001490904010000000000000054001500050501060A07001400150209" +
	"080000091F010A08000B240016000017000019A2011A26054023000602DF875701032F60CC060410C0B5240C806800000D15A103001C010000000149" +
	"0904010000000000000054001500050501060907001400150209080000091F010A08000B220016000017000019A2011A26054023000602E987570103" +
	"1460CC06041AC0B5240C806800000D1FA103001C0100000001490904010000000000000054001500050501060907001400150209080000091F010A08" +
	"000B210016000017000019A2011A26054023000602EE875701030E60CC060424C0B5240C806800000D29A103001C0100000001490904010000000000" +
	"000054001500050501060907001400150209080000091F010A08000B210016000017000019A2011A26054023000602E9875701031660CC06042EC0B5" +
	"240C806800000D33A103001C0100000001490904010000000000000054001500050501060907001400150209080000091F010A09000B230016000017" +
	"000019A2011A26054023000602E687570103FF5FCC060439C0B5240C806800000D3DA103001C01000000014909040100000000000000540015000505" +
	"01060907001400150209080000091F010A09000B230016000017000019A2011A26054023000602E887570103E75FCC060443C0B5240C806800000D46" +
	"A103001C0100000001490904010000000000000054001500050501060A070014001502090800000917010A08000B230016000017000019A2011A2605" +
	"4023000602E887570103D75FCC06044DC0B5240C806800000D50A103001C010000000149090401000000000000002A32300D0A"

func decodeAll(t *testing.T, profile string, frames ...[]byte) []*track.Message {
	t.Helper()
	nc, err := meitrack.NewCodec(json.RawMessage(profile))
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

func b(s string) []byte { return []byte(s) }

func hx(s string) []byte {
	v, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return v
}

// The documents' AAA reports: position in degrees, UTC time, km/h, the
// event codes as alerts, cells, analog values; the A10 answer completes a
// locate command.
//
// Covers: SIG-IMP-025
func TestDocumentFrames(t *testing.T) {
	ms := decodeAll(t, `{"analog": "t1", "analogHex": false}`, b(vA10Answer), b(vSOS), b(vFenceExit), b(vSpeeding), b(vHeartbeat), b(vA12Answer), b(vC01Answer), b(vE91Answer))
	if len(ms) != 8 {
		t.Fatalf("decoded %d frames", len(ms))
	}
	for i, m := range ms {
		if m == nil || m.IMEI != docIMEI || m.Raw == nil {
			t.Fatalf("frame %d: %+v", i, m)
		}
	}
	if !ms[0].Login || ms[1].Login {
		t.Fatal("the first frame of a connection identifies the tracker")
	}
	r := ms[0].Records[0]
	f := r.Fix
	if f.Time != time.Date(2010, 3, 13, 9, 37, 38, 0, time.UTC) || f.Lat != 22.543176 || f.Lon != 114.078448 || !f.Valid ||
		*f.Sats != 5 || *f.Speed != 2 || *f.Heading != 205 || *f.HDOP != 5 || *f.Alt != -14 {
		t.Fatalf("A10 answer fix %+v", f)
	}
	if r.Status["gsm"] != 22 || r.Status["runTime"] != int64(60) || r.Status["adc5"] != float64(914) || r.Status["ignition"] != false {
		t.Fatalf("A10 answer status %v", r.Status)
	}
	if v := r.Status["externalVoltage"].(float64); v < 11.7 || v > 11.8 { // 914 × 3.3 × 16 / 4096
		t.Fatalf("external voltage %v", v)
	}
	if ms[0].Response == nil || ms[0].Correlation != "Q:A10" || len(r.Alerts) != 0 {
		t.Fatalf("A10 answer %+v", ms[0])
	}
	if a := ms[1].Records[0].Alerts; len(a) != 1 || a[0].Type != "emergency" || a[0].Severity != track.Critical || a[0].Code != "1" || ms[1].Response != nil {
		t.Fatalf("SOS %+v", ms[1])
	}
	if a := ms[2].Records[0]; len(a.Alerts) != 1 || a.Alerts[0].Type != "geofence-exit" || a.Fix.Time != time.Date(2008, 2, 29, 12, 38, 12, 0, time.UTC) {
		t.Fatalf("geofence exit %+v", a)
	}
	sp := ms[3].Records[0]
	if len(sp.Alerts) != 1 || sp.Alerts[0].Type != "over-speed" || *sp.Fix.Speed != 61 || sp.Network == nil ||
		sp.Network.Cells[0].MCC != 460 || sp.Network.Cells[0].LAC != 0x10133 || sp.Network.Cells[0].CID != 0x4110 {
		t.Fatalf("speeding %+v %+v", sp, sp.Network)
	}
	if hb := ms[4].Records[0]; hb.Fix.Valid || hb.Status["event"] != 31 || len(hb.Alerts) != 0 {
		t.Fatalf("heartbeat %+v", hb)
	}
	if *ms[5].Response != "A12,OK" || ms[5].Failed || ms[5].Correlation != "V:A12" {
		t.Fatalf("A12 answer %+v", ms[5])
	}
	if *ms[6].Response != "C01,OK" || ms[6].Correlation != "M:C01" {
		t.Fatalf("C01 answer %+v", ms[6])
	}
	if ms[7].Correlation != "W:E91" || ms[7].Details["firmware"] != "FWV1.00" || ms[7].Details["serial"] != "12345678" {
		t.Fatalf("E91 answer %+v", ms[7])
	}
}

// The CCE batch of the CCE ID document: 12 packets, history (a batch, 25
// more cached), each with its position, time from 2000, event 35 and the
// voltages in hundredths.
//
// Covers: SIG-IMP-025
func TestDocumentCCE(t *testing.T) {
	ms := decodeAll(t, "", hx(vCCE))
	if len(ms) != 1 || ms[0] == nil {
		t.Fatalf("decoded %v", ms)
	}
	m := ms[0]
	if m.IMEI != "861585040494468" || len(m.Records) != 12 || len(m.Warnings) != 0 {
		t.Fatalf("batch %d records, %v", len(m.Records), m.Warnings)
	}
	r := m.Records[0]
	f := r.Fix
	if !r.History || f.Lat != 22.513623 || f.Lon != 114.057288 || f.Time != time.Date(2019, 7, 8, 8, 48, 30, 0, time.UTC) ||
		!f.Valid || *f.Sats != 10 || *f.Speed != 0 || *f.Heading != 287 || *f.HDOP != 0.7 || *f.Alt != 38 {
		t.Fatalf("first packet %+v", f)
	}
	if r.Status["event"] != 35 || r.Status["batteryVoltage"] != 4.18 || r.Status["externalVoltage"] != 13.18 ||
		r.Status["odometer"] != int64(26752) || r.Status["runTime"] != int64(237796) || r.Status["din2"] != true || r.Status["dout1"] != false {
		t.Fatalf("first packet status %v", r.Status)
	}
	if last := m.Records[11].Fix; last.Lat != 22.513640 || last.Time != time.Date(2019, 7, 8, 8, 50, 21, 0, time.UTC) {
		t.Fatalf("last packet %+v", last)
	}
}

// A frame whose checksum does not match is skipped with crcMismatch unless
// checkCrc is false; noise and an unreadable length resynchronise on the
// next header; a CCC batch and a server-direction frame are passed over and
// the stream reads on.
//
// Covers: SIG-IMP-025, SIG-IMP-026
func TestLenientFraming(t *testing.T) {
	bad := strings.Replace(vSOS, "*77", "*78", 1)
	ms := decodeAll(t, "", b(bad), b(vC01Answer))
	if len(ms) != 2 || ms[0] != nil || ms[1] == nil {
		t.Fatalf("strict: %v", ms)
	}
	nc, _ := meitrack.NewCodec(nil)
	_, err := nc().Decode(bufio.NewReader(strings.NewReader(bad)))
	var sk *track.Skip
	if !errors.As(err, &sk) || sk.Code != "crcMismatch" || sk.Setting != "profile.checkCrc" {
		t.Fatalf("bad checksum: %v", err)
	}
	if ms := decodeAll(t, `{"checkCrc": false}`, b(bad)); len(ms) != 1 || ms[0] == nil {
		t.Fatal("checkCrc false refused the frame")
	}
	ccc := meitrack.Encode(false, 'X', docIMEI, append([]byte("CCC,"), 1, 0, 0, 0, 0, 0))
	ms = decodeAll(t, "", b("garbage$$"), b("$$Zx9,"), ccc, b(vA10), b(vSOS))
	if n := len(ms); n < 3 || ms[n-1] == nil || ms[n-1].Records[0].Alerts[0].Type != "emergency" {
		t.Fatalf("resync: %v", ms)
	}
	for _, m := range ms[:len(ms)-1] {
		if m != nil {
			t.Fatalf("passed-over frame decoded: %+v", m)
		}
	}
	_, err = nc().Decode(bufio.NewReader(bytes.NewReader(ccc)))
	if !errors.As(err, &sk) || sk.Code != "unknownMessage" {
		t.Fatalf("CCC: %v", err)
	}
}

// Encode reproduces the documents' frames: length from the first comma to
// CR LF, checksum over the rest.
//
// Covers: SIG-IMP-025
func TestEncodeMatchesDocuments(t *testing.T) {
	for _, v := range []string{vA10, vA12, vC01, vF00, vA10Answer, vC01Answer, vE91Answer} {
		f, err := meitrack.ReadFrame(bufio.NewReader(strings.NewReader(v)))
		if err != nil || !f.CRCOK {
			t.Fatalf("%q: %v %+v", v, err, f)
		}
		body := f.Type
		if len(f.Data) > 0 {
			body += "," + string(f.Data)
		}
		if got := string(meitrack.Encode(f.Server, f.ID, f.IMEI, []byte(body))); got != v {
			t.Errorf("encode %q, want %q", got, v)
		}
	}
}
