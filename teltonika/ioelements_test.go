// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package teltonika_test

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"regexp"
	"testing"
	"time"

	"github.com/cB-Sigma/trackers/teltonika"
)

// The IO element table (Teltonika's public FMB AVL ID list) answers a
// name and unit per ID; names are unique camelCase keys, and the IDs the
// codec named before keep those names.
func TestIOElementTable(t *testing.T) {
	for id, want := range map[uint16][2]string{
		239: {"ignition", ""}, 66: {"externalVoltage", "V"}, 16: {"odometer", "m"}, 21: {"gsm", ""},
		1: {"din1", ""}, 179: {"dout1", ""}, 181: {"pdop", ""}, 182: {"hdop", ""}, 113: {"batteryLevel", "%"},
		72: {"dallasTemp1", "°C"}, 36: {"obdRpm", "rpm"}, 85: {"canRpm", "rpm"}, 25: {"bleTemp1", "°C"},
		256: {"vin", ""}, 78: {"iButton", ""}, 231: {"geofenceZone50", ""}, 155: {"geofenceZone1", ""},
	} {
		name, unit, ok := teltonika.IOName(id)
		if !ok || name != want[0] || unit != want[1] {
			t.Errorf("IOName(%d) = %q %q %v, want %v", id, name, unit, ok, want)
		}
	}
	if _, _, ok := teltonika.IOName(65000); ok {
		t.Error("unknown ID named")
	}
	camel := regexp.MustCompile(`^[a-z][a-zA-Z0-9]*$`)
	seen := map[string]uint16{}
	all := teltonika.IOElements()
	if len(all) < 100 {
		t.Fatalf("only %d IO elements", len(all))
	}
	for i, e := range all {
		if i > 0 && all[i-1].ID >= e.ID {
			t.Errorf("not sorted at %d", e.ID)
		}
		if !camel.MatchString(e.Name) {
			t.Errorf("%d: name %q is not camelCase", e.ID, e.Name)
		}
		if other, dup := seen[e.Name]; dup {
			t.Errorf("%q names both %d and %d", e.Name, other, e.ID)
		}
		seen[e.Name] = e.ID
	}
}

// By default the status keeps its keys (named defaults plus every raw
// element under "io"); with profile ioNames every listed element is added
// under its name, scaled and signed, alongside the unchanged "io" map.
func TestIONamesOption(t *testing.T) {
	at := time.Date(2026, 10, 11, 6, 0, 0, 0, time.UTC)
	rec := avlRecord{Time: at, Lat: 28.6, Lon: 77.2, Sats: 9,
		IO1: map[uint16]uint8{239: 1, 32: 0xF6 /* -10 °C */, 253: 2},
		IO2: map[uint16]uint16{66: 12600, 25: 0xFC18 /* BLE temperature -10.00 °C */, 9: 4500},
		IO4: map[uint16]uint32{72: 0xFFFFFF9C /* -10.0 °C */, 199: 1234},
		IO8: map[uint16]uint64{78: 0x0102030405060708}}
	pkt := tcpPacket(avlData(true, []avlRecord{rec}))

	m, err := decodeAfter(t, codec(t), vHandshake, string(hexOf(pkt)))
	if err != nil {
		t.Fatal(err)
	}
	st := m.Records[0].Status
	if st["ignition"] != true || st["externalVoltage"] != 12.6 || st["io"].(map[string]any)["72"] != uint64(0xFFFFFF9C) {
		t.Fatalf("default status %v", st)
	}
	for _, k := range []string{"dallasTemp1", "obdCoolantTemp", "iButton", "tripOdometer", "ain1"} {
		if _, has := st[k]; has {
			t.Fatalf("default status has %q: %v", k, st)
		}
	}

	m, err = decodeAfter(t, codecWith(t, `{"ioNames": true, "io": {"199": "trip"}}`), vHandshake, string(hexOf(pkt)))
	if err != nil {
		t.Fatal(err)
	}
	st = m.Records[0].Status
	want := map[string]any{"ignition": true, "externalVoltage": 12.6, "dallasTemp1": -10.0, "obdCoolantTemp": int64(-10),
		"bleTemp1": -10.0, "ain1": 4.5, "iButton": "0102030405060708", "trip": uint64(1234), "greenDrivingType": uint64(2)}
	for k, v := range want {
		if st[k] != v {
			t.Errorf("%s = %#v, want %#v", k, st[k], v)
		}
	}
	if _, has := st["tripOdometer"]; has {
		t.Error("profile io name did not replace the table name")
	}
	if st["io"].(map[string]any)["72"] != uint64(0xFFFFFF9C) {
		t.Errorf("raw io changed: %v", st["io"])
	}
}

// Codec 8 Extended variable-length elements: with ioNames, text elements
// (VIN) become text; others stay hex.
func TestIONamesVariable(t *testing.T) {
	d := []byte{teltonika.Codec8E, 1}
	d = binary.BigEndian.AppendUint64(d, uint64(time.Date(2026, 10, 11, 6, 0, 0, 0, time.UTC).UnixMilli()))
	d = append(d, 0)
	d = append(d, make([]byte, 4+4+2+2+1+2)...)
	d = binary.BigEndian.AppendUint16(d, 0) // event
	d = binary.BigEndian.AppendUint16(d, 2) // total
	for i := 0; i < 4; i++ {
		d = binary.BigEndian.AppendUint16(d, 0)
	}
	d = binary.BigEndian.AppendUint16(d, 2)
	d = binary.BigEndian.AppendUint16(d, 256)
	d = binary.BigEndian.AppendUint16(d, 17)
	d = append(d, "WVWZZZ1JZXW000001"...)
	d = binary.BigEndian.AppendUint16(d, 385)
	d = binary.BigEndian.AppendUint16(d, 2)
	d = append(d, 0xAB, 0xCD)
	d = append(d, 1)
	br := bufio.NewReader(bytes.NewReader(append(h(vHandshake), tcpPacket(d)...)))
	c := codecWith(t, `{"ioNames": true}`)
	_, _ = c.Decode(br)
	m, err := c.Decode(br)
	if err != nil {
		t.Fatal(err)
	}
	st := m.Records[0].Status
	if st["vin"] != "WVWZZZ1JZXW000001" || st["beacons"] != "ABCD" || st["io"].(map[string]any)["256"] != "5756575A5A5A314A5A5857303030303031" {
		t.Fatalf("status %v", st)
	}
}

func hexOf(b []byte) []byte {
	const digits = "0123456789ABCDEF"
	out := make([]byte, 0, 2*len(b))
	for _, c := range b {
		out = append(out, digits[c>>4], digits[c&15])
	}
	return out
}
