// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package teltonika_test

import (
	"encoding/binary"
	"math"
	"time"

	"github.com/cB-Sigma/trackers/teltonika"
	"github.com/cB-Sigma/trackers/track"
)

// The tests build frames themselves, so the library does not depend on
// its simulator (github.com/cB-Sigma/trackers-sim).

// avlRecord is one AVL record to encode.
type avlRecord struct {
	Time     time.Time
	Priority byte
	Lat, Lon float64
	Alt      int16
	Angle    uint16
	Sats     byte
	Speed    uint16
	Event    uint16
	IO1      map[uint16]uint8
	IO2      map[uint16]uint16
	IO4      map[uint16]uint32
	IO8      map[uint16]uint64
}

// avlData encodes records as an AVL data array (codec to second count) in
// Codec 8 or 8E.
func avlData(ext bool, recs []avlRecord) []byte {
	codec := byte(teltonika.Codec8)
	if ext {
		codec = teltonika.Codec8E
	}
	b := []byte{codec, byte(len(recs))}
	id := func(v uint16) {
		if ext {
			b = binary.BigEndian.AppendUint16(b, v)
		} else {
			b = append(b, byte(v))
		}
	}
	for _, r := range recs {
		b = binary.BigEndian.AppendUint64(b, uint64(r.Time.UnixMilli()))
		b = append(b, r.Priority)
		b = binary.BigEndian.AppendUint32(b, uint32(int32(math.Round(r.Lon*1e7))))
		b = binary.BigEndian.AppendUint32(b, uint32(int32(math.Round(r.Lat*1e7))))
		b = binary.BigEndian.AppendUint16(b, uint16(r.Alt))
		b = binary.BigEndian.AppendUint16(b, r.Angle)
		b = append(b, r.Sats)
		b = binary.BigEndian.AppendUint16(b, r.Speed)
		id(r.Event)
		id(uint16(len(r.IO1) + len(r.IO2) + len(r.IO4) + len(r.IO8)))
		id(uint16(len(r.IO1)))
		for k, v := range r.IO1 {
			id(k)
			b = append(b, v)
		}
		id(uint16(len(r.IO2)))
		for k, v := range r.IO2 {
			id(k)
			b = binary.BigEndian.AppendUint16(b, v)
		}
		id(uint16(len(r.IO4)))
		for k, v := range r.IO4 {
			id(k)
			b = binary.BigEndian.AppendUint32(b, v)
		}
		id(uint16(len(r.IO8)))
		for k, v := range r.IO8 {
			id(k)
			b = binary.BigEndian.AppendUint64(b, v)
		}
		if ext {
			b = binary.BigEndian.AppendUint16(b, 0)
		}
	}
	return append(b, byte(len(recs)))
}

// tcpPacket wraps an AVL data array with preamble, length and CRC.
func tcpPacket(data []byte) []byte {
	out := make([]byte, 4, len(data)+12)
	out = binary.BigEndian.AppendUint32(out, uint32(len(data)))
	out = append(out, data...)
	return binary.BigEndian.AppendUint32(out, uint32(track.CRC16IBM(data)))
}
