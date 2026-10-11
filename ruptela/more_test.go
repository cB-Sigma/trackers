// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package ruptela_test

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/cB-Sigma/trackers/ruptela"
	"github.com/cB-Sigma/trackers/track"
)

const imeiN = 356307042441013

// The text answers: configuration (2), version (3, the document's example
// "542C,00.03.09.10,668,22,1") and firmware update (4).
func TestTextAnswers(t *testing.T) {
	ms := decodeAll(t, "",
		ruptela.DeviceFrame(imeiN, ruptela.CmdConfig, []byte("@cfg_sts#10")),
		ruptela.DeviceFrame(imeiN, ruptela.CmdVersion, []byte("542C,00.03.09.10,668,22,1")),
		ruptela.DeviceFrame(imeiN, ruptela.CmdFirmware, []byte("*FU_OK|")))
	if len(ms) != 3 {
		t.Fatalf("%v", ms)
	}
	for _, m := range ms {
		if m == nil || m.Kind != "response" || m.Response == nil {
			t.Fatalf("%+v", m)
		}
	}
	d := ms[1].Details
	if *ms[1].Response != "542C,00.03.09.10,668,22,1" || d["bootloader"] != "542C" || d["firmware"] != "00.03.09.10" ||
		d["hardware"] != "668" || d["gsm"] != 22 || d["voltageOk"] != true {
		t.Fatalf("version %+v", d)
	}
}

// DTC packets: one record per code with its time, position, source and
// whether it is current or history; the server acknowledges with 109.
func TestDTC(t *testing.T) {
	ms := decodeAll(t, "", ruptela.DeviceFrame(imeiN, ruptela.CmdDTC, h(devDTCPayload)))
	if len(ms) != 1 || ms[0] == nil || len(ms[0].Records) != 2 || !bytes.Equal(ms[0].Reply, ruptela.ServerFrame(ruptela.AckDTC, []byte{1})) {
		t.Fatalf("%+v", ms)
	}
	r := ms[0].Records[0]
	if r.Status["dtc"] != "P0010" || r.Status["dtcSource"] != "obd" || r.History || r.Fix == nil ||
		r.Fix.Time != time.Unix(0x4E9CAF2C, 0).UTC() || r.Fix.Lon != float64(int32(0x07D608F1))/1e7 || r.Fix.Lat != float64(int32(0x1A1480BA))/1e7 {
		t.Fatalf("first %+v %+v", r, r.Fix)
	}
	if r := ms[0].Records[1]; r.Status["dtc"] != "P0011" || !r.History {
		t.Fatalf("second %+v", r)
	}
}

// A camera file arrives a packet at a time: the codec asks for the next
// packet (137, subcommand 2) and the last packet's message carries the
// file.
func TestFiles(t *testing.T) {
	ms := decodeAll(t, "", h(devFiles))
	if len(ms) != 1 || ms[0] == nil {
		t.Fatalf("%v", ms)
	}
	want := ruptela.ServerFrame(ruptela.Files, append(append([]byte{2, 0}, "5DDA1FAD"...), 0, 1))
	if !bytes.Equal(ms[0].Reply, want) || ms[0].Details["packets"] != 10 || ms[0].Kind != "picture" {
		t.Fatalf("% X %+v", ms[0].Reply, ms[0].Details)
	}
	pic := []byte{0xFF, 0xD8, 1, 2, 3, 0xFF, 0xD9}
	part := func(i int, data []byte) []byte {
		p := append([]byte{2, 1}, "00000ABC"...)
		p = binary.BigEndian.AppendUint16(p, 3)
		p = binary.BigEndian.AppendUint16(p, uint16(i))
		return ruptela.DeviceFrame(imeiN, ruptela.CmdFiles, append(p, data...))
	}
	ms = decodeAll(t, "", part(0, pic[:3]), part(1, pic[3:5]), part(2, pic[5:]))
	if len(ms) != 3 {
		t.Fatalf("%v", ms)
	}
	if ms[2].Reply != nil {
		t.Fatal("asked for a packet after the last")
	}
	p, ok := ruptela.PictureOf(ms[2])
	if !ok || p.Name != "00000ABC" || p.Source != 1 || !bytes.Equal(p.Data, pic) {
		t.Fatalf("%+v", p)
	}
	// The file list (subcommand 1) and a delete answer (3).
	list := append([]byte{1, 0, 2}, "5DDA1FAD5DDA2000"...)
	del := append(append([]byte{3, 0}, "5DDA1FAD"...), 0)
	ms = decodeAll(t, "", ruptela.DeviceFrame(imeiN, ruptela.CmdFiles, list), ruptela.DeviceFrame(imeiN, ruptela.CmdFiles, del))
	if names, _ := ms[0].Details["files"].([]string); len(names) != 2 || names[1] != "5DDA2000" || ms[0].Kind != "response" {
		t.Fatalf("list %+v", ms[0])
	}
	if !ms[1].Failed {
		t.Fatalf("delete %+v", ms[1])
	}
}

// Weighing data (32) is a record with the position and the scale's text;
// the transparent channel (14) is the serial data, acknowledged on its
// port so the device sends more.
func TestWeighingAndTransparent(t *testing.T) {
	w := binary.BigEndian.AppendUint32(nil, 1700000000)
	w = binary.BigEndian.AppendUint32(w, uint32(int32(25.2*1e7)))
	w = binary.BigEndian.AppendUint32(w, uint32(int32(54.6*1e7)))
	w = append(w, 1, 0)
	w = append(w, "W 12.50 kg"...)
	tr := append([]byte{1, 0, 0}, binary.BigEndian.AppendUint32(nil, 1700000001)...)
	tr = append(tr, 0xAA, 0x55)
	ms := decodeAll(t, "", ruptela.DeviceFrame(imeiN, ruptela.CmdWeighing, w), ruptela.DeviceFrame(imeiN, ruptela.CmdTransparent, tr))
	if len(ms) != 2 || ms[0] == nil || ms[1] == nil {
		t.Fatalf("%v", ms)
	}
	r := ms[0].Records[0]
	if r.Fix.Lat != 54.6 || r.Fix.Lon != 25.2 || !r.Fix.Valid || r.Status["weighing"] != "W 12.50 kg" || r.Status["port"] != "A" ||
		!bytes.Equal(ms[0].Reply, ruptela.ServerFrame(ruptela.AckWeighing, []byte{1})) {
		t.Fatalf("weighing %+v %+v", r, r.Fix)
	}
	r = ms[1].Records[0]
	if r.Status["serialData"] != "AA55" || r.Status["port"] != "B" || r.Time != time.Unix(1700000001, 0).UTC() ||
		!bytes.Equal(ms[1].Reply, ruptela.ServerFrame(ruptela.AckTransparent, []byte{1, 0, 0})) {
		t.Fatalf("transparent %+v % X", r, ms[1].Reply)
	}
}

// Packets the codec does not read but the device waits for an answer to
// (beacons 38, accident data 35) are acknowledged and passed over with a
// warning; others are passed over.
func TestAcknowledgedPassOver(t *testing.T) {
	nc, _ := ruptela.NewCodec(nil)
	for cmd, ack := range map[byte][]byte{
		ruptela.CmdBeacons:   ruptela.ServerFrame(ruptela.AckBeacons, []byte{1}),
		ruptela.CmdAccident:  ruptela.ServerFrame(ruptela.AckAccident, []byte{1}),
		ruptela.CmdTachoData: nil,
	} {
		_, err := nc().Decode(bufio.NewReader(bytes.NewReader(ruptela.DeviceFrame(imeiN, cmd, []byte{1, 2, 3}))))
		var sk *track.Skip
		if !errors.As(err, &sk) || sk.Code != "unknownMessage" || !bytes.Equal(sk.Reply, ack) {
			t.Errorf("command %d: %v % X", cmd, err, ack)
		}
	}
}

// SD card log data (34, after the server's request 134) carries records
// as command 1 or 68 does; they are history and are acknowledged with
// 134, subcommand 1.
func TestSDLog(t *testing.T) {
	rec := recordsPayload(true, false, rptRec{Time: time.Unix(1700000000, 0), Lat: 54.6, Lon: 25.2, Sats: 9, Event: 252})
	ms := decodeAll(t, "", ruptela.DeviceFrame(imeiN, ruptela.CmdSDLog, append([]byte{0x80}, rec...)))
	if len(ms) != 1 || ms[0] == nil || len(ms[0].Records) != 1 || !ms[0].Records[0].History || ms[0].Records[0].Fix.Lat != 54.6 ||
		!bytes.Equal(ms[0].Reply, ruptela.ServerFrame(ruptela.SDLog, []byte{1})) {
		t.Fatalf("%+v", ms)
	}
	ms = decodeAll(t, "", ruptela.DeviceFrame(imeiN, ruptela.CmdSDLog, []byte{0x20, 1}))
	if ms[0] == nil || ms[0].Kind != "response" || ms[0].Failed {
		t.Fatalf("enable answer %+v", ms[0])
	}
}

// The protocol's own command forms.
func TestBinaryCommands(t *testing.T) {
	nc, _ := ruptela.NewCodec(json.RawMessage(`{"commandIds": true}`))
	c := nc()
	for content, want := range map[string]struct {
		frame   []byte
		answers bool
	}{
		`{"getVersion": {}}`: {ruptela.ServerFrame(ruptela.GetVersion, nil), true},
		`{"setConnection": {"host": "gps.example.in", "port": 5000}}`:              {ruptela.ServerFrame(ruptela.SetConnection, []byte("gps.example.in,5000,TCP")), false},
		`{"setConnection": {"host": "10.0.0.1", "port": 5000, "protocol": "UDP"}}`: {ruptela.ServerFrame(ruptela.SetConnection, []byte("10.0.0.1,5000,UDP")), false},
		`{"setOdometer": {"value": 123456}}`:                                       {ruptela.ServerFrame(ruptela.SetOdometer, []byte{0, 1, 0xE2, 0x40}), false},
		`{"photoList": {"source": 1}}`:                                             {ruptela.ServerFrame(ruptela.Files, []byte{1, 1, 0, 0, 0, 0, 0x7F, 0xFF, 0xFF, 0xFF}), true},
		`{"photo": {"name": "5DDA1FAD"}}`:                                          {ruptela.ServerFrame(ruptela.Files, append(append([]byte{2, 0}, "5DDA1FAD"...), 0, 0)), true},
	} {
		var v any
		_ = json.Unmarshal([]byte(content), &v)
		f, answers, err := c.Command("1", v, 1)
		if err != nil || answers != want.answers || !bytes.Equal(f, want.frame) {
			t.Errorf("%s: % X %v %v", content, f, answers, err)
		}
		if corr, _ := c.(track.Correlator).Correlation(v, 1); corr != "" {
			t.Errorf("%s: correlation %q", content, corr)
		}
	}
	for _, bad := range []string{`{"setConnection": {"host": "a,b", "port": 1}}`, `{"setConnection": {"host": "a", "port": 70000}}`,
		`{"setOdometer": {"value": -1}}`, `{"photo": {"name": "TOOLONGNAME"}}`, `{"photoList": {"source": 9}}`, `{"getVersion": {}, "x": 1}`} {
		var v any
		_ = json.Unmarshal([]byte(bad), &v)
		if _, _, err := c.Command("1", v, 1); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}
