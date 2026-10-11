// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package meitrack

import (
	"errors"
	"strconv"
	"time"

	"github.com/cB-Sigma/trackers/track"
)

// CCC, the older binary batch. Meitrack publishes no description of it; the
// layout is the one Traccar's decoder reads (facts only) and its published
// device packets confirm: after "CCC," an 8-byte header (a 2-byte value, the
// record length as 2 bytes little endian, 52 in every packet seen, and 4
// bytes not read), then records of that length, little endian:
//
//	event u8, latitude i32 (1e-6 degrees), longitude i32, time u32 (seconds
//	from 2000), valid u8, satellites u8, GSM level u8, speed u16 (km/h),
//	heading u16, HDOP u16 (tenths), altitude i16 (m), mileage u32, run time
//	u32, MCC u16, MNC u16, LAC u16, cell ID u16, I/O status u16, AD1 u16,
//	battery u16 (hundredths of a volt), external power u16 (hundredths of a
//	volt), geofence u32
//
// The server confirms the batch with "CCC,<records read>".

const cccRecord = 52

var errCCC = errors.New("CCC header names a record length under 52 bytes or data that does not divide into records")

func (c *codec) ccc(b []byte) ([]track.Record, error) {
	if len(b) < 8 {
		return nil, errCCC
	}
	size := int(b[2]) | int(b[3])<<8
	data := b[8:]
	if size < cccRecord || len(data)%size != 0 {
		return nil, errCCC
	}
	n := len(data) / size
	out := make([]track.Record, 0, n)
	for i := 0; i < n; i++ {
		r := &reader{b: data[i*size : i*size+cccRecord]}
		ev := r.u8()
		lat := int32(r.u32())
		lon := int32(r.u32())
		ts := r.u32()
		valid := r.u8() == 1
		sats := r.u8()
		gsm := r.u8()
		speed, heading, hdop := r.u16(), r.u16(), r.u16()
		alt := int16(r.u16())
		odo, run := r.u32(), r.u32()
		mcc, mnc, lac, cid := r.u16(), r.u16(), r.u16(), r.u16()
		io, ad1, bat, power := r.u16(), r.u16(), r.u16(), r.u16()
		fence := r.u32()
		x := &track.Fix{Time: epoch2000.Add(time.Duration(ts) * time.Second), Lat: float64(lat) / 1e6, Lon: float64(lon) / 1e6,
			Valid: valid, Sats: track.I(sats), Speed: track.F(float64(speed)), Heading: track.F(float64(heading)),
			HDOP: track.F(float64(hdop) / 10), Alt: track.F(float64(alt))}
		st := map[string]any{"event": ev, "gsm": gsm, "odometer": int64(odo), "runTime": int64(run), "ioStatus": io,
			"adc1": float64(ad1), "batteryVoltage": float64(bat) / 100, "externalVoltage": float64(power) / 100}
		if ev == 20 || ev == 21 {
			st["geofence"] = int(fence)
		}
		rec := track.Record{Fix: x, Time: x.Time, Status: st, History: n > 1}
		if mcc > 0 {
			rec.Network = &track.Network{Cells: []track.Cell{{MCC: mcc, MNC: mnc, LAC: lac, CID: int64(cid)}}}
		}
		rec.Alerts = c.alerts(ev, st)
		out = append(out, rec)
	}
	return out, nil
}

// cccConfirm is the server's confirmation of a CCC batch.
func cccConfirm(f *Frame, n int) []byte {
	return Encode(true, f.ID, f.IMEI, []byte("CCC,"+strconv.Itoa(n)))
}
