// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package calamp_test

import (
	"bufio"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/trackers/calamp"
	"github.com/cB-Sigma/trackers/track"
)

// Device datagrams quoted in Traccar's CalAmpProtocolDecoderTest
// (Apache-2.0), used as test vectors.
const (
	// Event report (type 2), acknowledged service, from a unit in Pune.
	vEvent = "83051633033459010101028afd59ae7c1459ae7c140b06bbce2c01520e0000d916000001b900450900005affa50f091f00260d040000000f24000001b90000000000003714"
	// Mini event report (type 10).
	vMini = "830543321494860101010a0080560b5a5e0eadd0291becf3c500f005090f1f3305000003010040c0a600000000000000008b12a102"
	// User data (type 4) with a full position header.
	vUser = "830547643586340101010400105f9c39ba5f9c302eeb36d5bddf39df700000000000000000003400040321ff9f4f0087080200001c30783330304544383946333335303139303030303030343637450d0a"
	// ID report (type 3).
	vID = "830545321041830101010300010000333862000023c301000000004532104183ffffff353816051610691f420040163953294fffffffffffffffff8996604211639032949f4f54413a317c303b302c317c343b302c34004f5441535441543a302c302c302c302c302c222200564255533a342c322e302e302c343533323130343138332c5630312e30332e30312e34302c5630312e30332e30312e33312c2c0056494e2d494e464f3a56494e3d31464d5a5537324539355a4137303032362c4445562d5245474e3d55532c535256522d5245474e3d555300"
	// Event report with accumulators of type 1 (threshold and mask first).
	vEvent2 = "8305454205067001010102008157a9bddc57a96aaa17cdb98fccc1a457000056ac00000000000007250000ff8f000e00082711570000000000ffff101b00003148000010680000000000000000000000050000000000000000000005b0000000000000289600000000000000000000069b00000000000008e400000000000000000000000000000003000000010000070f"
)

func datagram(t *testing.T, profile, h string) []*track.Message {
	t.Helper()
	nc, err := calamp.NewCodec([]byte(profile))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := hex.DecodeString(h)
	ms, err := nc().(track.DatagramCodec).DecodeDatagram(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 {
		t.Fatalf("%d messages", len(ms))
	}
	return ms
}

func near(a, b float64) bool { return a-b < 1e-6 && b-a < 1e-6 }

func TestEventReport(t *testing.T) {
	m := datagram(t, "", vEvent)[0]
	if m.IMEI != "1633033459" || m.Kind != "event" {
		t.Fatalf("%q %s", m.IMEI, m.Kind)
	}
	// The acknowledgement: service 2, type 1 (ACK), the sequence number,
	// the type acknowledged, ACK code 0, spare, application version.
	if hex.EncodeToString(m.Reply) != "02018afd020000000000" {
		t.Errorf("reply % x", m.Reply)
	}
	r := m.Records[0]
	f := r.Fix
	at := time.Unix(0x59ae7c14, 0).UTC()
	if f == nil || !f.Valid || !f.Time.Equal(at) || !r.Time.Equal(at) || !near(f.Lat, 18.499067) || !near(f.Lon, 73.8284046) ||
		!near(*f.Alt, 555.74) || !near(*f.Speed, 441*0.036) || *f.Heading != 69 || *f.Sats != 9 {
		t.Fatalf("fix %+v", f)
	}
	for k, v := range map[string]any{"event": 13, "eventIndex": 38, "rssi": -91, "carrier": 90, "ignition": true, "din4": true, "din5": false,
		"acc0": uint32(0x0f24), "acc1": uint32(0x1b9), "acc3": uint32(0x3714), "hdop": 9, "commState": 15, "unitStatus": 0} {
		if r.Status[k] != v {
			t.Errorf("%s = %#v, want %#v", k, r.Status[k], v)
		}
	}
	if len(r.Alerts) != 0 {
		t.Errorf("alerts %v", r.Alerts)
	}
	// A profile maps event codes (PEG-defined) to alert types.
	r = datagram(t, `{"alerts": {"13": "emergency"}}`, vEvent)[0].Records[0]
	if len(r.Alerts) != 1 || r.Alerts[0].Type != "emergency" || r.Alerts[0].Code != "13" {
		t.Errorf("alerts %v", r.Alerts)
	}
	r = datagram(t, "", vEvent2)[0].Records[0]
	if r.Status["acc0"] == nil || r.Status["accThreshold"] == nil {
		t.Errorf("type-1 accumulators %v", r.Status)
	}
}

func TestMiniEvent(t *testing.T) {
	m := datagram(t, "", vMini)[0]
	r := m.Records[0]
	f := r.Fix
	if m.IMEI != "4332149486" || m.Kind != "event" || f == nil || !f.Valid || !near(f.Lat, 24.6272041) || !near(f.Lon, 46.8513733) ||
		*f.Heading != 240 || *f.Speed != 5 || *f.Sats != 9 || !f.Time.Equal(time.Unix(0x560b5a5e, 0).UTC()) {
		t.Fatalf("%q %+v", m.IMEI, f)
	}
	if r.Status["event"] != 51 || r.Status["acc4"] != uint32(0x8b12a102) || r.Status["ignition"] != true {
		t.Errorf("%v", r.Status)
	}
	if hex.EncodeToString(m.Reply) != "020100800a0000000000" {
		t.Errorf("reply % x", m.Reply)
	}
}

func TestUserDataAndIDReport(t *testing.T) {
	m := datagram(t, "", vUser)[0]
	r := m.Records[0]
	if m.IMEI != "4764358634" || m.Kind != "userData" || r.Fix == nil {
		t.Fatalf("%q %s %+v", m.IMEI, m.Kind, r)
	}
	if !strings.HasPrefix(r.Status["userData"].(string), "0x300ED89F") || r.Status["userDataRoute"] != 2 {
		t.Errorf("user data %q", r.Status)
	}
	m = datagram(t, "", vID)[0]
	if m.IMEI != "4532104183" || m.Kind != "id" || len(m.Records) != 0 || len(m.Reply) == 0 {
		t.Errorf("ID report %+v", m)
	}
}

// The unit's ACK/NAK of a command completes it; a NAK fails it.
func TestAckFromUnit(t *testing.T) {
	for _, tc := range []struct {
		h      string
		failed bool
	}{
		{"8305123456789f0101" + "0201" + "000a" + "04" + "00" + "00" + "000000", false},
		{"8305123456789f0101" + "0201" + "000b" + "04" + "03" + "00" + "000000", true},
	} {
		m := datagram(t, "", tc.h)[0]
		if m.IMEI != "123456789" || m.Kind != "response" || m.Response == nil || m.Failed != tc.failed || m.Reply != nil {
			t.Errorf("%s: %+v", tc.h, m)
		}
	}
	if m := datagram(t, "", "8305123456789f0101"+"0201000a040000000000")[0]; m.Correlation != "4/000A" {
		t.Errorf("correlation %q", m.Correlation)
	}
}

// Text commands go to the unit as user data it acknowledges; named
// commands have no LM Direct form unless the profile gives one.
func TestCommands(t *testing.T) {
	nc, _ := calamp.NewCodec(nil)
	c := nc()
	f, answers, err := c.Command("4764358634", map[string]any{"text": "HELLO"}, 10)
	if err != nil || !answers || hex.EncodeToString(f) != "0104000a00000005"+hex.EncodeToString([]byte("HELLO")) {
		t.Errorf("%x %v %v", f, answers, err)
	}
	if corr, strict := c.(track.Correlator).Correlation(map[string]any{"text": "HELLO"}, 10); corr != "4/000A" || !strict {
		t.Errorf("correlation %q", corr)
	}
	if dc, ok := c.(track.DatagramCommander); !ok || !dc.DatagramCommands() {
		t.Error("not a datagram commander")
	}
	f, answers, err = c.Command("x", map[string]any{"hex": "0107000102"}, 1)
	if err != nil || answers || hex.EncodeToString(f) != "0107000102" {
		t.Errorf("hex: %x %v %v", f, answers, err)
	}
	for _, a := range track.Actions {
		content := map[string]any{"action": a}
		if a == track.ActionInterval {
			content["seconds"] = 60.0
		}
		if _, _, err := c.Command("x", content, 1); !errors.Is(err, track.ErrUnsupported) {
			t.Errorf("%s: %v", a, err)
		}
	}
	nc, err = calamp.NewCodec([]byte(`{"namedCommands": {"engineStop": "STOP {imei}"}}`))
	if err != nil {
		t.Fatal(err)
	}
	f, _, err = nc().Command("77", map[string]any{"action": "engineStop"}, 2)
	if err != nil || hex.EncodeToString(f) != "0104000200000007"+hex.EncodeToString([]byte("STOP 77")) {
		t.Errorf("template: %x %v", f, err)
	}
}

func TestBadInput(t *testing.T) {
	nc, _ := calamp.NewCodec(nil)
	c := nc()
	for _, h := range []string{"", "83", "830a12", "8305123456789f010102"} {
		b, _ := hex.DecodeString(h)
		if _, err := c.(track.DatagramCodec).DecodeDatagram(b); err == nil {
			t.Errorf("%q accepted", h)
		}
	}
	// LM Direct is UDP: the stream decoder refuses.
	if _, err := c.Decode(bufio.NewReader(strings.NewReader("x"))); err == nil || errors.Is(err, track.ErrSkip) {
		t.Errorf("TCP: %v", err)
	}
	for _, p := range []string{`{"alerts": {"x": "emergency"}}`, `{"alerts": {"300": "emergency"}}`, `{"other": 1}`} {
		if _, err := calamp.NewCodec([]byte(p)); err == nil {
			t.Errorf("%s accepted", p)
		}
	}
}
