// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package h02_test

import (
	"fmt"
	"math"
	"strings"
	"time"
)

// The tests build frames themselves, so the library does not depend on
// its simulator (github.com/cB-Sigma/trackers-sim).

// binPos is one position for a binary record.
type binPos struct {
	Time     time.Time
	Lat, Lon float64
	Speed    float64 // knots
	Course   int
	Valid    bool
	Status   uint32 // 0 means FFFFFBFF: nothing active, ACC off
}

func bcdByte(s string) byte { return (s[0]-'0')<<4 | (s[1] - '0') }

// degMin is |v| as degrees (degDigits wide) and minutes with 4 decimals.
func degMin(v float64, degDigits int) string {
	v = math.Abs(v)
	d := math.Floor(v)
	m := (v - d) * 60
	return fmt.Sprintf("%0*d%07.4f", degDigits, int(d), m)
}

// binaryFrame is a 32-byte '$' record of a 10-digit id.
func binaryFrame(id string, p binPos) []byte {
	tm := p.Time.UTC()
	digits := id + tm.Format("150405") + tm.Format("020106")
	lat := strings.Replace(degMin(p.Lat, 2), ".", "", 1)
	lon := strings.Replace(degMin(p.Lon, 3), ".", "", 1)
	var flags byte
	if p.Valid {
		flags |= 0x02
	}
	if p.Lat >= 0 {
		flags |= 0x04
	}
	if p.Lon >= 0 {
		flags |= 0x08
	}
	b := []byte{'$'}
	for i := 0; i < len(digits); i += 2 {
		b = append(b, bcdByte(digits[i:i+2]))
	}
	for i := 0; i < 8; i += 2 {
		b = append(b, bcdByte(lat[i:i+2]))
	}
	b = append(b, 0x00) // battery / reserved
	for i := 0; i < 8; i += 2 {
		b = append(b, bcdByte(lon[i:i+2]))
	}
	b = append(b, (lon[8]-'0')<<4|flags)
	sc := fmt.Sprintf("%03d%03d", int(math.Round(p.Speed)), p.Course)
	for i := 0; i < 6; i += 2 {
		b = append(b, bcdByte(sc[i:i+2]))
	}
	w := p.Status
	if w == 0 {
		w = 0xFFFFFBFF
	}
	b = append(b, byte(w>>24), byte(w>>16), byte(w>>8), byte(w))
	b = append(b, 0xFF, 0x00, 0x01) // user alarm flag, reserved, record number
	return b
}
