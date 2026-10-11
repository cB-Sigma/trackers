package gt06_test

import (
	"encoding/hex"
	"testing"

	"github.com/cB-Sigma/trackers/gt06"
)

// 0x94 information packets (in 0x7878 or 0x7979 frames) become status values by
// sub-protocol; they are not answered.
//
// Covers: SIG-IPE-688
func TestInformationPackets(t *testing.T) {
	login := hex.EncodeToString(gt06.Encode(gt06.PLogin, []byte{0x03, 0x59, 0x33, 0x90, 0x75, 0x01, 0x08, 0x31}, 1))
	info := func(sub byte, data ...byte) string {
		return hex.EncodeToString(gt06.Encode(gt06.PInfo, append([]byte{sub}, data...), 2))
	}
	ids := append(append([]byte{0x03, 0x59, 0x33, 0x90, 0x75, 0x01, 0x08, 0x31}, // IMEI
		0x04, 0x04, 0x45, 0x01, 0x23, 0x45, 0x67, 0x89), // IMSI 404450123456789
		0x89, 0x91, 0x45, 0x01, 0x23, 0x45, 0x67, 0x89, 0x01, 0x23) // ICCID
	ms := decodeAll(t, `{}`, login, info(0x00, 0x04, 0xB0), info(0x04, []byte("ALM1=C4;DYD=01;")...), info(0x05, 0x01), info(0x0A, ids...), info(0x33, 0xAB))
	if len(ms) != 6 {
		t.Fatalf("%d messages", len(ms))
	}
	want := []map[string]any{
		{"externalVoltage": 12.0},
		{"terminalStatus": "ALM1=C4;DYD=01;"},
		{"doorOpen": true},
		{"imsi": "404450123456789", "iccid": "89914501234567890123"},
		{"info0x33": "AB"},
	}
	for i, w := range want {
		m := ms[i+1]
		if m.Reply != nil || len(m.Records) != 1 {
			t.Fatalf("info %d: %+v", i, m)
		}
		for k, v := range w {
			if m.Records[0].Status[k] != v {
				t.Errorf("info %d: %s = %v, want %v", i, k, m.Records[0].Status[k], v)
			}
		}
	}
}
