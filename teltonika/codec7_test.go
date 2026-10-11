// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package teltonika_test

import (
	"bytes"
	"testing"
	"time"
)

// Codec 7 (GH3000 family) packets from Traccar's decoder tests
// (TeltonikaProtocolDecoderTest.java, Traccar v6.16.0, Apache-2.0).
const (
	// Four records: IO only, two GPS fixes, then signal, operator and
	// 1-, 2- and 4-byte IO without a fix.
	vCodec7a = "0000000000000055070450aa14320201f00150aa17f3031f42332a4c4193d68c008d00020901f00150aa1b6a031f423383f54193624f009d00000a01f00150aa1c230fc01a0000552b040164f400dd00f0010143100c0105000000050400006846"
	// Four records with every location field, cell and operator. Traccar's
	// copy ends one byte short in its CRC field (Traccar does not check
	// it); the CRC here is the computed 0x04E5.
	vCodec7b = "00000000000000c7070441bf9db00fff425adbd741ca6e1e009e1205070001030b160000601a02015e02000314006615000a160067010500000ce441bf9d920fff425adbb141ca6fc900a2b218070001030b160000601a02015e02000314006615000a160067010500000cc641bf9d740fff425adbee41ca739200b6c91e070001030b1f0000601a02015f02000314006615000a160066010500000ca841bf9cfc0fff425adba041ca70c100b93813070001030b1f0000601a02015f02000314002315000a160025010500000c3004000004E5"
	// Two GPS-only records with a cell.
	vCodec7c = "000000000000003107024c61410b013f4231c2c141d0beb9003d000005006483ff4c6140eb013f4231c2c141d0beb9003d000005006483ff02000041df"
)

func near(a, b float64) bool { return a-b < 1e-5 && b-a < 1e-5 }

// Codec 7: a 4-byte time in seconds since 2007-01-01 with the priority in
// its top two bits, a global mask of the parts present, a location mask
// of the GPS fields present (float latitude and longitude, 1-byte angle in
// 1/256 turns and speed), and IO groups of 1, 2 and 4 bytes.
func TestCodec7(t *testing.T) {
	gh := time.Date(2007, 1, 1, 0, 0, 0, 0, time.UTC)

	m, err := decodeAfter(t, codec(t), vHandshake, vCodec7a)
	if err != nil || len(m.Records) != 4 || !bytes.Equal(m.Reply, []byte{0, 0, 0, 4}) {
		t.Fatalf("codec 7 a %+v %v", m, err)
	}
	r := m.Records[0]
	if r.Fix != nil || !r.Time.Equal(gh.Add(0x10aa1432*time.Second)) || r.Status["priority"] != 1 ||
		r.Status["io"].(map[string]any)["240"] != uint64(1) {
		t.Fatalf("record 1 %+v", r)
	}
	f := m.Records[1].Fix
	if f == nil || !f.Valid || !near(f.Lat, 44.791306) || !near(f.Lon, 18.479759) || *f.Alt != 141 || *f.Heading != 0 ||
		*f.Speed != 2 || *f.Sats != 9 || !f.Time.Equal(gh.Add(0x10aa17f3*time.Second)) {
		t.Fatalf("record 2 fix %+v", f)
	}
	r = m.Records[3]
	io := r.Status["io"].(map[string]any)
	if r.Fix != nil || r.Status["operator"] != uint64(21803) || r.Status["signal"] != 26 || io["1"] != uint64(100) ||
		io["244"] != uint64(0) || io["67"] != uint64(0x100c) || io["5"] != uint64(5) {
		t.Fatalf("record 4 %+v", r)
	}
	// GH3000 IO IDs are not the FMB ones: no FMB names are given to them.
	if _, named := r.Status["din1"]; named {
		t.Fatalf("FMB name on a GH3000 element: %v", r.Status)
	}

	m, err = decodeAfter(t, codec(t), vHandshake, vCodec7b)
	if err != nil || len(m.Records) != 4 {
		t.Fatalf("codec 7 b %+v %v", m, err)
	}
	r = m.Records[0]
	f = r.Fix
	if f == nil || !near(f.Lat, 54.714687) || !near(f.Lon, 25.303768) || *f.Alt != 158 || !near(*f.Heading, 0x12*360.0/256) ||
		*f.Speed != 5 || *f.Sats != 7 || r.Status["priority"] != 1 {
		t.Fatalf("b record 1 %+v %+v", r, f)
	}
	if r.Network == nil || len(r.Network.Cells) != 1 || r.Network.Cells[0].LAC != 1 || r.Network.Cells[0].CID != 0x030b ||
		r.Network.Cells[0].MCC != 246 || r.Network.Cells[0].MNC != 2 || r.Network.Cells[0].RSSI != nil ||
		r.Status["signal"] != 0x16 || r.Status["operator"] != uint64(24602) {
		t.Fatalf("b record 1 network %+v", r.Network)
	}
	if io := r.Status["io"].(map[string]any); io["20"] != uint64(0x66) || io["5"] != uint64(0xce4) {
		t.Fatalf("b record 1 io %v", io)
	}

	m, err = decodeAfter(t, codec(t), vHandshake, vCodec7c)
	if err != nil || len(m.Records) != 2 || m.Records[1].Fix == nil || *m.Records[1].Fix.Sats != 5 ||
		m.Records[1].Network.Cells[0].CID != 0x83ff || m.Records[1].Network.Cells[0].LAC != 0x64 {
		t.Fatalf("codec 7 c %+v %v", m, err)
	}
}
