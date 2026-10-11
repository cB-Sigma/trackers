package teltonika_test

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/cB-Sigma/trackers/teltonika"
	"github.com/cB-Sigma/trackers/track"
)

func h(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// Packets from Teltonika's public protocol description (CRCs checked).
const (
	vHandshake = "000F333536333037303432343431303133"
	vCodec8    = "000000000000003608010000016B40D8EA30010000000000000000000000000000000105021503010101425E0F01F10000601A014E0000000000000000010000C7CF"
	vCodec8E   = "000000000000004A8E010000016B412CEE000100000000000000000000000000000000010005000100010100010011001D00010010015E2C880002000B000000003544C87A000E000000001DD7E06A00000100002994"
	vCodec12   = "000000000000000F0C010500000007676574696E666F0100004312" // "getinfo"
	vUDP       = "003DCAFE0105000F33353230393330383634303336353508010000016B4F815B30010000000000000000000000000000000103021503010101425DBC000001"
	vUDPAck    = "0005CAFE010501"
)

func codec(t *testing.T) track.Codec {
	nc, err := teltonika.NewCodec(nil)
	if err != nil {
		t.Fatal(err)
	}
	return nc()
}

// Covers: SIG-IPE-488
func TestPublishedPackets(t *testing.T) {
	c := codec(t)
	br := bufio.NewReader(bytes.NewReader(h(vHandshake + vCodec8 + vCodec8E)))
	m, err := c.Decode(br)
	if err != nil || m.IMEI != "356307042441013" || !bytes.Equal(m.Reply, []byte{1}) || !bytes.Equal(m.Reject, []byte{0}) {
		t.Fatalf("handshake %+v %v", m, err)
	}
	m, err = c.Decode(br)
	if err != nil || len(m.Records) != 1 || !bytes.Equal(m.Reply, []byte{0, 0, 0, 1}) {
		t.Fatalf("codec 8 %+v %v", m, err)
	}
	r := m.Records[0]
	if r.Fix.Time != time.UnixMilli(0x16B40D8EA30).UTC() || r.Fix.Valid {
		t.Fatalf("fix %+v", r.Fix)
	}
	if r.Status["gsm"] != uint64(3) || r.Status["din1"] != true || r.Status["externalVoltage"] != 24.079 || r.Status["priority"] != 1 {
		t.Fatalf("status %v", r.Status)
	}
	if io := r.Status["io"].(map[string]any); io["241"] != uint64(24602) || io["78"] != uint64(0) {
		t.Fatalf("io %v", io)
	}
	m, err = c.Decode(br)
	if err != nil || len(m.Records) != 1 {
		t.Fatalf("codec 8E %+v %v", m, err)
	}
	if io := m.Records[0].Status["io"].(map[string]any); io["17"] != uint64(0x1D) || io["16"] != uint64(0x015E2C88) || io["11"] != uint64(0x3544C87A) || io["14"] != uint64(0x1DD7E06A) {
		t.Fatalf("8E io %v", io)
	}
	if m.Records[0].Status["odometer"] != uint64(0x015E2C88) {
		t.Fatalf("odometer %v", m.Records[0].Status)
	}
	// Codec 12 command vector: our encoder builds the same bytes.
	f, answers, err := c.Command("356307042441013", map[string]any{"text": "getinfo"}, 1)
	if err != nil || !answers || !bytes.Equal(f, h(vCodec12)) {
		t.Fatalf("codec 12 % X", f)
	}
	// UDP.
	ms, err := c.(track.DatagramCodec).DecodeDatagram(h(vUDP))
	if err != nil || len(ms) != 1 || ms[0].IMEI != "352093086403655" || !bytes.Equal(ms[0].Reply, h(vUDPAck)) {
		t.Fatalf("udp %+v %v", ms, err)
	}
	if ms[0].Records[0].Status["externalVoltage"] != 23.996 {
		t.Fatalf("udp status %v", ms[0].Records[0].Status)
	}
}

// Covers: SIG-IPE-488
func TestBadCRCNotAcknowledged(t *testing.T) {
	c := codec(t)
	bad := h(vCodec8)
	bad[len(bad)-1] ^= 0xFF
	br := bufio.NewReader(bytes.NewReader(append(h(vHandshake), bad...)))
	if _, err := c.Decode(br); err != nil {
		t.Fatal(err)
	}
	var sk *track.Skip
	if _, err := c.Decode(br); !errors.As(err, &sk) || sk.Code != "crcMismatch" {
		t.Fatalf("bad CRC: %v", err)
	}
	// Truncated AVL data (read whole) is passed over with a warning, not a
	// panic, and not acknowledged (SIG-IPE-3540).
	trunc := tcpPacket(h("080100000000"))
	br = bufio.NewReader(bytes.NewReader(append(h(vHandshake), trunc...)))
	c = codec(t)
	_, _ = c.Decode(br)
	if m, err := c.Decode(br); !errors.As(err, &sk) || sk.Code != "avlUnreadable" || m != nil {
		t.Fatalf("truncated: %v", err)
	}
}

// Covers: SIG-IPE-488
func TestEventAlerts(t *testing.T) {
	c := codec(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	recs := []avlRecord{
		{Time: now, Priority: 2, Lat: 28.6, Lon: 77.2, Sats: 7, Speed: 30},
		{Time: now, Priority: 1, Lat: 28.6, Lon: 77.2, Sats: 7, Event: 253, IO1: map[uint16]uint8{253: 2}},
		{Time: now, Priority: 1, Lat: 28.6, Lon: 77.2, Sats: 7, Event: 252, IO1: map[uint16]uint8{252: 1}},
		{Time: now, Priority: 1, Lat: 28.6, Lon: 77.2, Sats: 7, Event: 239, IO1: map[uint16]uint8{239: 0}},
	}
	pkt := append(h(vHandshake), tcpPacket(avlData(true, recs))...)
	br := bufio.NewReader(bytes.NewReader(pkt))
	_, _ = c.Decode(br)
	m, err := c.Decode(br)
	if err != nil || len(m.Records) != 4 {
		t.Fatalf("%v %v", m, err)
	}
	want := []string{"emergency", "harsh-braking", "main-power-removed", "ignition-off"}
	for i, w := range want {
		if a := m.Records[i].Alerts; len(a) != 1 || a[0].Type != w {
			t.Fatalf("record %d alerts %v, want %s", i, a, w)
		}
	}
	if m.Records[0].Alerts[0].Severity != "critical" || !m.Records[0].Fix.Valid {
		t.Fatalf("%+v", m.Records[0])
	}
}
