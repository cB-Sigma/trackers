// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package ruptela_test

import (
	"encoding/binary"
	"sort"
	"time"
)

// The tests build frames themselves, so the library does not depend on
// its simulator (github.com/cB-Sigma/trackers-sim).

// rptRec is one record to encode.
type rptRec struct {
	Time     time.Time
	Lat, Lon float64
	Alt      float64 // metres
	Angle    float64 // degrees
	Speed    int     // km/h
	Sats     int
	HDOP     float64
	Priority int
	Event    int
	// IO elements by size in bytes (1, 2, 4 or 8).
	IO1, IO2, IO4, IO8 map[uint16]uint64
}

// recordsPayload builds a command 1 (ext false) or 68 payload.
func recordsPayload(ext, left bool, recs ...rptRec) []byte {
	b := []byte{0, byte(len(recs))}
	if left {
		b[0] = 1
	}
	for _, r := range recs {
		b = binary.BigEndian.AppendUint32(b, uint32(r.Time.Unix()))
		b = append(b, 0)
		if ext {
			b = append(b, 0) // record extension: not split
		}
		b = append(b, byte(r.Priority))
		b = binary.BigEndian.AppendUint32(b, uint32(int32(r.Lon*1e7)))
		b = binary.BigEndian.AppendUint32(b, uint32(int32(r.Lat*1e7)))
		b = binary.BigEndian.AppendUint16(b, uint16(int16(r.Alt*10)))
		b = binary.BigEndian.AppendUint16(b, uint16(r.Angle*100))
		b = append(b, byte(r.Sats))
		b = binary.BigEndian.AppendUint16(b, uint16(r.Speed))
		b = append(b, byte(r.HDOP*10))
		if ext {
			b = binary.BigEndian.AppendUint16(b, uint16(r.Event))
		} else {
			b = append(b, byte(r.Event))
		}
		for i, m := range []map[uint16]uint64{r.IO1, r.IO2, r.IO4, r.IO8} {
			size := 1 << i
			ids := make([]int, 0, len(m))
			for id := range m {
				ids = append(ids, int(id))
			}
			sort.Ints(ids)
			b = append(b, byte(len(ids)))
			for _, id := range ids {
				if ext {
					b = binary.BigEndian.AppendUint16(b, uint16(id))
				} else {
					b = append(b, byte(id))
				}
				v := m[uint16(id)]
				var vb [8]byte
				binary.BigEndian.PutUint64(vb[:], v)
				b = append(b, vb[8-size:]...)
			}
		}
	}
	return b
}
