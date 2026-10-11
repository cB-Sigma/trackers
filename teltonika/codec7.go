// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package teltonika

import (
	"errors"
	"math"
	"strconv"
	"time"

	"github.com/cB-Sigma/trackers/track"
)

// ghEpoch is Codec 7's time origin: its records count seconds from here.
var ghEpoch = time.Date(2007, 1, 1, 0, 0, 0, 0, time.UTC)

// Codec 7 masks. The global mask says which parts a record has; the
// location mask which GPS and cell fields follow.
const (
	ghGPS  = 1 << 0
	ghIO1  = 1 << 1
	ghIO2  = 1 << 2
	ghIO4  = 1 << 3
	locLL  = 1 << 0 // latitude, longitude (float32 each)
	locAlt = 1 << 1
	locAng = 1 << 2 // 1 byte, 256 steps per turn
	locSpd = 1 << 3 // 1 byte, km/h
	locSat = 1 << 4
	locCel = 1 << 5 // LAC, cell ID
	locSig = 1 << 6 // signal quality
	locOp  = 1 << 7 // operator code (MCC and MNC digits)
)

// records7 reads Codec 7 records after the codec byte: count, records,
// count. GH device IO IDs are not the FMB ones, so they stay raw under
// "io"; IO 222 set is the SOS button.
func records7(r *rd) ([]track.Record, error) {
	n := int(r.u8())
	var out []track.Record
	for i := 0; i < n && r.err == nil; i++ {
		tp := r.u32()
		at := ghEpoch.Add(time.Duration(tp&0x3FFFFFFF) * time.Second)
		st := map[string]any{"priority": int(tp >> 30)}
		rec := track.Record{Time: at, Status: st}
		global := r.u8()
		if global&ghGPS != 0 {
			loc := r.u8()
			f := &track.Fix{Time: at}
			hasLL := loc&locLL != 0
			if hasLL {
				f.Lat = float64(math.Float32frombits(uint32(r.u32())))
				f.Lon = float64(math.Float32frombits(uint32(r.u32())))
			}
			if loc&locAlt != 0 {
				a := float64(r.u16())
				f.Alt = &a
			}
			if loc&locAng != 0 {
				h := float64(r.u8()) * 360 / 256
				f.Heading = &h
			}
			if loc&locSpd != 0 {
				s := float64(r.u8())
				f.Speed = &s
			}
			if loc&locSat != 0 {
				s := int(r.u8())
				f.Sats = &s
			}
			var cell *track.Cell
			if loc&locCel != 0 {
				cell = &track.Cell{LAC: int(r.u16()), CID: int64(r.u16())}
			}
			if loc&locSig != 0 {
				st["signal"] = int(r.u8())
			}
			if loc&locOp != 0 {
				op := r.u32()
				st["operator"] = op
				if cell != nil {
					cell.MCC, cell.MNC = splitOperator(op)
				}
			}
			if cell != nil {
				rec.Network = &track.Network{Cells: []track.Cell{*cell}}
			}
			if hasLL {
				f.Valid = (f.Lat != 0 || f.Lon != 0) && (f.Sats == nil || *f.Sats > 0)
				rec.Fix = f
			}
		}
		raw := map[string]any{}
		for _, g := range []struct {
			bit  uint64
			read func() uint64
		}{{ghIO1, r.u8}, {ghIO2, r.u16}, {ghIO4, r.u32}} {
			if global&g.bit == 0 {
				continue
			}
			cnt := int(r.u8())
			for j := 0; j < cnt && r.err == nil; j++ {
				id := r.u8()
				v := g.read()
				raw[strconv.Itoa(int(id))] = v
				if id == 222 && v == 1 {
					rec.Alerts = append(rec.Alerts, track.NewAlert("emergency", "io-222"))
				}
			}
		}
		st["io"] = raw
		out = append(out, rec)
	}
	if r.err != nil {
		return nil, r.err
	}
	if n2 := int(r.u8()); r.err != nil || n2 != n {
		return nil, errors.New("teltonika: record counts differ")
	}
	return out, nil
}

// splitOperator splits an operator code (MCC then a 2- or 3-digit MNC,
// such as 24602 or 405854) into MCC and MNC; 0, 0 when it is not one.
func splitOperator(op uint64) (int, int) {
	switch {
	case op >= 10000 && op <= 99999:
		return int(op / 100), int(op % 100)
	case op >= 100000 && op <= 999999:
		return int(op / 1000), int(op % 1000)
	}
	return 0, 0
}
