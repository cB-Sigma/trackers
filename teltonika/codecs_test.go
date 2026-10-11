package teltonika_test

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"

	"github.com/cB-Sigma/trackers/teltonika"
	"github.com/cB-Sigma/trackers/track"
)

func codecWith(t *testing.T, profile string) track.Codec {
	t.Helper()
	nc, err := teltonika.NewCodec(json.RawMessage(profile))
	if err != nil {
		t.Fatal(err)
	}
	return nc()
}

// codec16Record builds one Codec 16 record: 2-byte event and IO IDs,
// 1-byte counts, and the generation type after the event ID.
func codec16Data(ts time.Time, gen byte) []byte {
	d := []byte{teltonika.Codec16, 1}
	d = binary.BigEndian.AppendUint64(d, uint64(ts.UnixMilli()))
	d = append(d, 0) // priority
	d = binary.BigEndian.AppendUint32(d, uint32(int32(77.2*1e7)))
	d = binary.BigEndian.AppendUint32(d, uint32(int32(28.6*1e7)))
	d = binary.BigEndian.AppendUint16(d, 216)    // altitude
	d = binary.BigEndian.AppendUint16(d, 90)     // angle
	d = append(d, 9)                             // satellites
	d = binary.BigEndian.AppendUint16(d, 42)     // speed
	d = binary.BigEndian.AppendUint16(d, 0x0105) // event IO ID 261
	d = append(d, gen)
	d = append(d, 3) // total IO count
	d = append(d, 1) // 1-byte values
	d = binary.BigEndian.AppendUint16(d, 239)
	d = append(d, 1)
	d = append(d, 1) // 2-byte values
	d = binary.BigEndian.AppendUint16(d, 66)
	d = binary.BigEndian.AppendUint16(d, 12600)
	d = append(d, 1) // 4-byte values
	d = binary.BigEndian.AppendUint16(d, 300)
	d = binary.BigEndian.AppendUint32(d, 7)
	d = append(d, 0) // 8-byte values
	return append(d, 1)
}

// Codec 16 AVL data (Teltonika's public protocol description: 2-byte IO
// IDs with 1-byte counts and a generation type) is read like Codec 8.
//
// Covers: SIG-IPE-686
func TestCodec16(t *testing.T) {
	c := codec(t)
	now := time.Now().UTC().Truncate(time.Millisecond)
	br := bufio.NewReader(bytes.NewReader(append(h(vHandshake), tcpPacket(codec16Data(now, 7))...)))
	if _, err := c.Decode(br); err != nil {
		t.Fatal(err)
	}
	m, err := c.Decode(br)
	if err != nil || len(m.Records) != 1 || !bytes.Equal(m.Reply, []byte{0, 0, 0, 1}) {
		t.Fatalf("codec 16 %+v %v", m, err)
	}
	r := m.Records[0]
	if !r.Fix.Valid || r.Fix.Lat != 28.6 || r.Fix.Lon != 77.2 || *r.Fix.Speed != 42 || !r.Fix.Time.Equal(now) {
		t.Fatalf("fix %+v", r.Fix)
	}
	if r.Status["ignition"] != true || r.Status["externalVoltage"] != 12.6 || r.Status["generation"] != "periodical" {
		t.Fatalf("status %v", r.Status)
	}
	if io := r.Status["io"].(map[string]any); io["300"] != uint64(7) {
		t.Fatalf("io %v", io)
	}
}

// Codec 13 is a one-way device message with a timestamp; Codec 14
// commands carry the IMEI, and the device's answer is either the response
// (type 0x06) or "not my IMEI" (type 0x11), which fails the command.
//
// Covers: SIG-IPE-687
func TestCodec13And14(t *testing.T) {
	// Codec 13: timestamp 2019-06-10 10:04:46 UTC and text "hello".
	d13 := []byte{teltonika.Codec13, 1, 0x05, 0, 0, 0, 9, 0x5C, 0xFE, 0x2A, 0x3E}
	d13 = append(append(d13, "hello"...), 1)
	c := codec(t)
	br := bufio.NewReader(bytes.NewReader(append(h(vHandshake), tcpPacket(d13)...)))
	_, _ = c.Decode(br)
	m, err := c.Decode(br)
	if err != nil || m.Response != nil || len(m.Records) != 1 || m.Records[0].Status["message"] != "hello" ||
		!m.Records[0].Time.Equal(time.Unix(0x5CFE2A3E, 0).UTC()) {
		t.Fatalf("codec 13 %+v %v", m, err)
	}

	// Codec 14 command: IMEI as 8 BCD bytes with a leading zero digit.
	c = codecWith(t, `{"commandCodec":14}`)
	f, answers, err := c.Command("352093081452251", map[string]any{"text": "getver"}, 1)
	if err != nil || !answers {
		t.Fatal(err)
	}
	data := f[8 : len(f)-4]
	want := append([]byte{teltonika.Codec14, 1, 0x05, 0, 0, 0, 14, 0x03, 0x52, 0x09, 0x30, 0x81, 0x45, 0x22, 0x51}, "getver"...)
	want = append(want, 1)
	if !bytes.Equal(data, want) || binary.BigEndian.Uint32(f[4:8]) != uint32(len(want)) ||
		binary.BigEndian.Uint32(f[len(f)-4:]) != uint32(track.CRC16IBM(want)) {
		t.Fatalf("codec 14 frame % X", f)
	}
	ans := func(typ byte, text string) *track.Message {
		d := []byte{teltonika.Codec14, 1, typ}
		d = binary.BigEndian.AppendUint32(d, uint32(8+len(text)))
		d = append(d, 0x03, 0x52, 0x09, 0x30, 0x81, 0x45, 0x22, 0x51)
		d = append(append(d, text...), 1)
		br := bufio.NewReader(bytes.NewReader(append(h(vHandshake), tcpPacket(d)...)))
		cc := codecWith(t, `{"commandCodec":14}`)
		_, _ = cc.Decode(br)
		m, err := cc.Decode(br)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	if m := ans(0x06, "Ver:03.25.14"); m.Response == nil || *m.Response != "Ver:03.25.14" || m.Failed {
		t.Fatalf("codec 14 answer %+v", m)
	}
	if m := ans(0x11, ""); m.Response == nil || !m.Failed {
		t.Fatalf("codec 14 not-my-IMEI %+v", m)
	}
	if _, err := teltonika.NewCodec(json.RawMessage(`{"commandCodec":13}`)); err == nil {
		t.Error("commandCodec 13 accepted")
	}
}
