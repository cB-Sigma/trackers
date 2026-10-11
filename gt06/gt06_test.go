package gt06_test

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/trackers/gt06"
	"github.com/cB-Sigma/trackers/track"
)

func h(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

// Frames published in the GT06/Concox protocol documents (as quoted in open
// test suites such as Traccar's, Apache-2.0: see NOTICE); the CRCs below
// were checked independently.
const (
	vLogin     = "78780D01012345678901234500018CDD0D0A"
	vLoginAck  = "7878050100 01D9DC0D0A"
	vLocation  = "78781f120f0a140e150bc505e51e780293a9e800540000f601006e0055da00035f240d0a"
	vLocBadCRC = "78781F120B081D112E10CC027AC7EB0C46584900148F01CC00287D001FB8000380810D0A" // the document's example; its CRC is wrong
	vStatus    = "78780a13440604000201baaf540d0a"
	vAlarm     = "787825160b051b093523cf027ac8360c4657b30014000901cc00266a001e1740050400020008d7b10d0a"
	vLoc22     = "787822220F0C1D023305C9027AC8180C46586000140001CC00287D001F71000001000820860D0A"
	vAnswer21  = "797900262100000000020043006f006d006d0061006e00640020006500720072006f0072002100236e850d0a"
)

func decodeAll(t *testing.T, profile string, frames ...string) []*track.Message {
	t.Helper()
	nc, err := gt06.NewCodec(json.RawMessage(profile))
	if err != nil {
		t.Fatal(err)
	}
	c := nc()
	var buf bytes.Buffer
	for _, f := range frames {
		buf.Write(h(f))
	}
	br := bufio.NewReader(&buf)
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

// Covers: SIG-IPE-485
func TestPublishedFrames(t *testing.T) {
	if got := track.CRCITU(h("0D0101234567890123450001")); got != 0x8CDD {
		t.Fatalf("CRC-ITU %04X", got)
	}
	ms := decodeAll(t, "", vLogin, vLocation, vStatus, vAlarm, vLoc22, vAnswer21)
	if len(ms) != 6 {
		t.Fatalf("decoded %d frames", len(ms))
	}
	if ms[0].IMEI != "123456789012345" || !ms[0].Login || !bytes.Equal(ms[0].Reply, h(vLoginAck)) {
		t.Fatalf("login %+v % X", ms[0], ms[0].Reply)
	}
	f := ms[1].Records[0].Fix
	if f.Time != time.Date(2015, 10, 20, 14, 21, 11, 0, time.UTC) || !f.Valid || *f.Sats != 5 {
		t.Fatalf("location %+v", f)
	}
	if lat, lon := f.Lat, f.Lon; lat < 54.94 || lat > 54.95 || lon < 24.01 || lon > 24.02 || ms[1].Reply != nil {
		t.Fatalf("lat %v lon %v reply %v", lat, lon, ms[1].Reply)
	}
	st := ms[2].Records[0].Status
	if st["ignition"] != false || st["gpsTracking"] != true || st["batteryLevel"] != 6 || st["gsm"] != 4 || ms[2].Reply == nil {
		t.Fatalf("status %v", st)
	}
	al := ms[3].Records[0]
	if al.Fix == nil || !al.Fix.Valid || al.Status["gsm"] != 4 || len(al.Alerts) != 0 || ms[3].Reply == nil {
		t.Fatalf("alarm %+v", al)
	}
	if r := ms[4].Records[0]; r.Fix.Time != time.Date(2015, 12, 29, 2, 51, 5, 0, time.UTC) || !r.History {
		t.Fatalf("0x22 %+v", r)
	}
	if *ms[5].Response != "Command error!" || !ms[5].Failed {
		t.Fatalf("answer %q", *ms[5].Response)
	}
}

// Covers: SIG-IPE-485
func TestBadCRCIsSkippedUnlessProfileAllows(t *testing.T) {
	ms := decodeAll(t, "", vLocBadCRC, vStatus)
	if len(ms) != 2 || ms[0] != nil || ms[1] == nil {
		t.Fatalf("strict: %v", ms)
	}
	ms = decodeAll(t, `{"checkCrc": false}`, vLocBadCRC)
	if len(ms) != 1 || ms[0] == nil {
		t.Fatal("tolerant profile refused the frame")
	}
	f := ms[0].Records[0].Fix
	if f.Lat < 23.11 || f.Lat > 23.12 || f.Lon < 114.40 || f.Lon > 114.41 || *f.Heading != 143 {
		t.Fatalf("fix %+v", f)
	}
	// Noise before a frame is skipped.
	ms = decodeAll(t, "", "0102030D0A"+vStatus)
	if len(ms) != 1 || ms[0] == nil {
		t.Fatalf("resync %v", ms)
	}
	if _, err := gt06.NewCodec(json.RawMessage(`{"alarms": {"x": "y"}}`)); err == nil {
		t.Fatal("a bad alarm code was accepted")
	}
}
