// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package teltonika_test

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"github.com/cB-Sigma/trackers/teltonika"
	"github.com/cB-Sigma/trackers/track"
)

// Packets from Teltonika's public "Codec" wiki page (CRCs checked by the
// tests): Codec 15 "Hello!\n" from IMEI 123456789123456, Codec 13 "hello
// lets test\r\n", and Codec 14 getver with its ACK and nACK answers.
const (
	vHandshake15 = "000F313233343536373839313233343536" // IMEI 123456789123456
	vCodec15     = "000000000000001B0F010B00000013654B65A4012345678912345648656C6C6F210A01000093D6"
	vCodec13Wiki = "000000000000001D0D01060000001564E8328168656C6C6F206C65747320746573740D0A0100003548"
	vCodec14Cmd  = "00000000000000160E01050000000E0352093081452251676574766572010000D2C1"
	vCodec14Ack  = "00000000000000AB0E0106000000A303520930814522515665723A30332E31382E31345F3034204750533A41584E5F352E31305F333333332048773A464D42313230" +
		"204D6F643A313520494D45493A33353230393330383134353232353120496E69743A323031382D31312D323220373A313320557074696D653A3137323334204D4143" +
		"3A363042444430303136323631205350433A312830292041584C3A30204F42443A3020424C3A312E362042543A340100007AAE"
	// The page's nACK example carries CRC 0x32AC; its data computes to
	// 0x635E, so it is read with checkCrc off.
	vCodec14Nack = "00000000000000100E011100000008035209308145246801000032AC"
)

func decodeAfter(t *testing.T, c track.Codec, handshake, packet string) (*track.Message, error) {
	t.Helper()
	br := bufio.NewReader(bytes.NewReader(h(handshake + packet)))
	if _, err := c.Decode(br); err != nil {
		t.Fatal(err)
	}
	return c.Decode(br)
}

// Codec 15 is a one-way device message carrying a timestamp and the
// device's IMEI with the text; it becomes a status "message" at its own
// time and needs no answer.
func TestCodec15(t *testing.T) {
	m, err := decodeAfter(t, codec(t), vHandshake15, vCodec15)
	if err != nil {
		t.Fatal(err)
	}
	if m.IMEI != "123456789123456" || m.Response != nil || len(m.Reply) != 0 || len(m.Records) != 1 {
		t.Fatalf("codec 15 %+v", m)
	}
	r := m.Records[0]
	if r.Status["message"] != "Hello!\n" || !r.Time.Equal(time.Unix(0x654B65A4, 0)) || r.Fix != nil {
		t.Fatalf("codec 15 record %+v", r)
	}

	text, at, imei, err := teltonika.ParseCodec15(h(vCodec15)[8 : len(h(vCodec15))-4])
	if err != nil || text != "Hello!\n" || imei != "123456789123456" || at.Unix() != 0x654B65A4 {
		t.Fatalf("ParseCodec15 %q %v %q %v", text, at, imei, err)
	}

	// The frame builder makes the published packet byte for byte.
	f, err := teltonika.Codec15Frame("123456789123456", 0x0B, time.Unix(0x654B65A4, 0), "Hello!\n")
	if err != nil || !bytes.Equal(f, h(vCodec15)) {
		t.Fatalf("Codec15Frame % X %v", f, err)
	}

	// A message naming another device's IMEI is passed over with a warning.
	_, err = decodeAfter(t, codec(t), vHandshake, vCodec15)
	var sk *track.Skip
	if !errors.As(err, &sk) || sk.Warning.Code != "imeiMismatch" {
		t.Fatalf("other IMEI: %v", err)
	}

	// Truncated and overrunning sizes are refused, not read past the end.
	bad := []byte{teltonika.Codec15, 1, 0x0B, 0, 0, 0, 0x40, 0x65, 0x4B, 0x65, 0xA4}
	if _, _, _, err := teltonika.ParseCodec15(append(bad, 1)); err == nil {
		t.Error("overrunning size accepted")
	}
	short := []byte{teltonika.Codec15, 1, 0x0B, 0, 0, 0, 8, 0x65, 0x4B, 0x65, 0xA4, 1, 2, 3, 4, 1}
	if _, _, _, err := teltonika.ParseCodec15(short); err == nil {
		t.Error("size below timestamp and IMEI accepted")
	}
}

// The wiki's own Codec 13 and Codec 14 packets decode: the Codec 13 text
// with its time, the getver command frame byte for byte, the ACK answer as
// the response and the nACK as a failed command.
func TestCodec13And14WikiPackets(t *testing.T) {
	m, err := decodeAfter(t, codec(t), vHandshake, vCodec13Wiki)
	if err != nil || len(m.Records) != 1 || m.Records[0].Status["message"] != "hello lets test\r\n" ||
		m.Records[0].Time.Unix() != 0x64E83281 {
		t.Fatalf("codec 13 %+v %v", m, err)
	}
	f, err := teltonika.Codec14Frame("352093081452251", "getver")
	if err != nil || !bytes.Equal(f, h(vCodec14Cmd)) {
		t.Fatalf("codec 14 command % X %v", f, err)
	}
	c14 := codecWith(t, `{"commandCodec":14}`)
	m, err = decodeAfter(t, c14, vHandshake, vCodec14Ack)
	if err != nil || m.Response == nil || m.Failed || len(*m.Response) != 0xA3-8 ||
		!bytes.HasPrefix([]byte(*m.Response), []byte("Ver:03.18.14_04 ")) {
		t.Fatalf("codec 14 ACK %+v %v", m, err)
	}
	m, err = decodeAfter(t, codecWith(t, `{"commandCodec":14, "checkCrc": false}`), vHandshake, vCodec14Nack)
	if err != nil || m.Response == nil || !m.Failed {
		t.Fatalf("codec 14 nACK %+v %v", m, err)
	}
	// The published packets' data sizes and CRCs hold.
	for _, v := range []string{vCodec15, vCodec13Wiki, vCodec14Cmd, vCodec14Ack} {
		b := h(v)
		n := binary.BigEndian.Uint32(b[4:8])
		if int(n)+12 != len(b) || uint32(track.CRC16IBM(b[8:8+n])) != binary.BigEndian.Uint32(b[8+n:]) {
			t.Errorf("%s: size or CRC", v[:24])
		}
	}
}
