// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package meitrack_test

import (
	"bufio"
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/trackers/meitrack"
)

// The fields of a published D00 packet: file name, packet count, packet
// number, then the picture's bytes (a JPEG starts FF D8).
func TestParsePicturePacket(t *testing.T) {
	raw := hx(vD00Head)
	i := bytes.Index(raw, []byte(",D00,"))
	p, err := meitrack.ParsePicturePacket(raw[i+5:])
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "180224072614_C1E109_N1U1D1.jpg" || p.Total != 14 || p.Index != 0 || len(p.Data) < 2 || p.Data[0] != 0xFF || p.Data[1] != 0xD8 {
		t.Fatalf("%+v", p)
	}
	// The document calls the picture data hexadecimal: hex text is read too.
	p, err = meitrack.ParsePicturePacket([]byte("a.jpg,1,0,FFD8FFD9"))
	if err != nil || !bytes.Equal(p.Data, []byte{0xFF, 0xD8, 0xFF, 0xD9}) {
		t.Fatalf("hex data: %+v %v", p, err)
	}
	for _, bad := range []string{"", "a.jpg", "a.jpg,0,0,x", "a.jpg,2,2,x", "a.jpg,x,0,x", ",1,0,x", "a.jpg,99999,0,x"} {
		if _, err := meitrack.ParsePicturePacket([]byte(bad)); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

// pictureFrames splits pic into D00 packets of size bytes, as a tracker
// sends them.
func pictureFrames(name string, pic []byte, size int) [][]byte {
	total := (len(pic) + size - 1) / size
	var out [][]byte
	for i := 0; i < total; i++ {
		end := min((i+1)*size, len(pic))
		body := append([]byte(fmt.Sprintf("D00,%s,%d,%d,", name, total, i)), pic[i*size:end]...)
		out = append(out, meitrack.Encode(false, 'O', docIMEI, body))
	}
	return out
}

// D00 packets are reassembled into the picture; after every eighth packet
// the codec asks for the next eight (D00,<name>,<next>); each packet
// answers the D00 command; the last one carries the picture.
func TestPictureReassembly(t *testing.T) {
	pic := make([]byte, 0, 2000)
	pic = append(pic, 0xFF, 0xD8)
	for i := 0; len(pic) < 1998; i++ {
		pic = append(pic, byte(i), '*', '\r', '\n', ',')
	}
	pic = append(pic[:1998], 0xFF, 0xD9)
	frames := pictureFrames("0215080432_C2E03.jpg", pic, 100) // 20 packets
	ms := decodeAll(t, "", frames...)
	if len(ms) != 20 {
		t.Fatalf("decoded %d", len(ms))
	}
	for i, m := range ms {
		if m == nil || m.Kind != "picture" || m.Response == nil || m.Correlation != "O:D00" {
			t.Fatalf("packet %d: %+v", i, m)
		}
		want := ""
		if i == 7 || i == 15 {
			want = string(meitrack.Encode(true, 'O', docIMEI, []byte(fmt.Sprintf("D00,0215080432_C2E03.jpg,%d", i+1))))
		}
		if string(m.Reply) != want {
			t.Fatalf("packet %d reply %q, want %q", i, m.Reply, want)
		}
		got, ok := meitrack.PictureOf(m)
		if ok != (i == 19) {
			t.Fatalf("packet %d: picture %v", i, ok)
		}
		if ok && (got.Name != "0215080432_C2E03.jpg" || !bytes.Equal(got.Data, pic)) {
			t.Fatalf("picture %q %d bytes", got.Name, len(got.Data))
		}
	}
	// Out of order and repeated packets still make the picture.
	shuffled := append([][]byte{frames[3], frames[3]}, frames[:3]...)
	shuffled = append(shuffled, frames[4:]...)
	ms = decodeAll(t, "", shuffled...)
	if p, ok := meitrack.PictureOf(ms[len(ms)-1]); !ok || !bytes.Equal(p.Data, pic) {
		t.Fatal("out-of-order packets were not reassembled")
	}
	// A packet of another picture starts over.
	other := pictureFrames("b.jpg", []byte{0xFF, 0xD8, 1, 0xFF, 0xD9}, 3)
	ms = decodeAll(t, "", frames[0], other[0], other[1])
	if p, ok := meitrack.PictureOf(ms[2]); !ok || p.Name != "b.jpg" || len(p.Data) != 5 {
		t.Fatalf("second picture %+v", ms[2])
	}
}

// A picture larger than the bound is dropped with a warning.
func TestPictureTooLarge(t *testing.T) {
	body := []byte(fmt.Sprintf("D00,big.jpg,%d,0,", meitrack.MaxPicture/1000+2))
	body = append(body, bytes.Repeat([]byte{1}, 2000)...)
	ms := decodeAll(t, "", meitrack.Encode(false, 'A', docIMEI, body))
	if len(ms) != 1 || ms[0] != nil {
		t.Fatalf("%+v", ms)
	}
}

// The D01 picture list: names split over packets are joined once every
// packet has come.
func TestPictureList(t *testing.T) {
	p0 := meitrack.Encode(false, 'A', docIMEI, []byte("D01,2,0,0506162517_C1E03.jpg|0506162517_C1"))
	p1 := meitrack.Encode(false, 'A', docIMEI, []byte("D01,2,1,E11.jpg|0215080547_C1E03.jpg|"))
	ms := decodeAll(t, "", p0, p1)
	if len(ms) != 2 || ms[0].Correlation != "A:D01" || ms[0].Details["packets"] != 2 || ms[0].Details["pictures"] != nil {
		t.Fatalf("first %+v", ms[0])
	}
	want := []string{"0506162517_C1E03.jpg", "0506162517_C1E11.jpg", "0215080547_C1E03.jpg"}
	if got, _ := ms[1].Details["pictures"].([]string); strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("list %v", ms[1].Details)
	}
}

// An AAA report of event 39 names the picture taken; with fetchPictures
// the codec asks for it at once.
func TestPictureEvent(t *testing.T) {
	aaa := meitrack.Encode(false, 'G', docIMEI, []byte("AAA,39,22.538169,114.075958,100313095653,A,3,21,4,46,5,581,0,148,0|0|10133|4172,0000,166|204|205|2709|878,0918101221_C2E03.jpg"))
	ms := decodeAll(t, "", aaa)
	if ms[0].Records[0].Status["picture"] != "0918101221_C2E03.jpg" || ms[0].Reply != nil {
		t.Fatalf("%+v", ms[0])
	}
	ms = decodeAll(t, `{"fetchPictures": true, "confirmEvents": true}`, aaa)
	want := string(meitrack.Encode(true, 'G', docIMEI, []byte("AFF,1"))) + string(meitrack.Encode(true, 'G', docIMEI, []byte("D00,0918101221_C2E03.jpg,0")))
	if string(ms[0].Reply) != want {
		t.Fatalf("reply %q", ms[0].Reply)
	}
}

// PictureRequest is the document's D00 request.
func TestPictureRequest(t *testing.T) {
	nc, _ := meitrack.NewCodec(nil)
	f, answers, err := nc().Command(docIMEI, map[string]any{"text": meitrack.PictureRequest("0215080432_C2E03.jpg", 0)}, 15)
	// The document's example: @@O48,353358017784062,D00,0215080432_C2E03.jpg,0*DB
	if err != nil || !answers || string(f) != "@@O48,353358017784062,D00,0215080432_C2E03.jpg,0*DB\r\n" {
		t.Fatalf("%q %v", f, err)
	}
}

// CCC batches (Traccar's published packets): 52-byte records with the
// position, time from 2000, cell and voltages; the codec confirms the
// count it read with CCC,<n>.
func TestCCC(t *testing.T) {
	ms := decodeAll(t, "", hx(vCCC1), hx(vCCC18))
	if len(ms) != 2 || ms[0] == nil || ms[1] == nil {
		t.Fatalf("%+v", ms)
	}
	m := ms[0]
	if m.IMEI != "369800014090021" || len(m.Records) != 1 || len(m.Warnings) != 0 {
		t.Fatalf("%+v", m)
	}
	r := m.Records[0]
	f := r.Fix
	if f.Time != time.Date(2014, 5, 24, 4, 59, 49, 0, time.UTC) || f.Lat != -7.266504 || f.Lon != 112.743651 || f.Valid || *f.Sats != 9 {
		t.Fatalf("fix %+v", f)
	}
	if r.Status["event"] != 35 || r.Status["gsm"] != 19 || r.Status["odometer"] != int64(80083) || r.Status["runTime"] != int64(180092) ||
		r.Status["batteryVoltage"] != 4.19 || r.History {
		t.Fatalf("status %v", r.Status)
	}
	if c := r.Network.Cells[0]; c.MCC != 510 || c.MNC != 1 || c.LAC != 13572 || c.CID != 60414 {
		t.Fatalf("cell %+v", c)
	}
	if string(m.Reply) != string(meitrack.Encode(true, 'X', "369800014090021", []byte("CCC,1"))) {
		t.Fatalf("reply %q", m.Reply)
	}
	m = ms[1]
	if len(m.Records) != 18 || !m.Records[0].History || string(m.Reply) != string(meitrack.Encode(true, 'G', "369800013460674", []byte("CCC,18"))) {
		t.Fatalf("batch %d %q", len(m.Records), m.Reply)
	}
	first, last := m.Records[0], m.Records[17]
	if first.Status["event"] != 1 || len(first.Alerts) != 1 || first.Alerts[0].Type != "emergency" || m.Kind != "emergency" {
		t.Fatalf("first %+v kind %s", first, m.Kind)
	}
	if last.Status["event"] != 32 || !last.Fix.Valid || *last.Fix.Speed != 11 || *last.Fix.Heading != 4 || *last.Fix.HDOP != 1.3 ||
		*last.Fix.Alt != 276 || last.Status["externalVoltage"] != 14.11 {
		t.Fatalf("last %+v %v", last.Fix, last.Status)
	}
	// A CCC whose header names a record length under 52 is passed over.
	bad := meitrack.Encode(false, 'X', docIMEI, append([]byte("CCC,"), 2, 1, 20, 0, 1, 0, 0, 0))
	nc, _ := meitrack.NewCodec(nil)
	if _, err := nc().Decode(bufio.NewReader(bytes.NewReader(bad))); err == nil {
		t.Fatal("short CCC record length accepted")
	}
}
