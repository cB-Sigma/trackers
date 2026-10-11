// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package suntech

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cB-Sigma/trackers/track"
)

// skipZip passes over a compressed report: 0x02, a 2-byte length, the
// body and a 1-byte footer.
func skipZip(r *bufio.Reader, head []byte) error {
	n := 3 + int(binary.BigEndian.Uint16(head[1:3])) + 1
	if _, err := r.Discard(n); err != nil {
		return io.ErrUnexpectedEOF
	}
	return skipMsg("zipFormat", fmt.Sprintf("%d bytes", n),
		"A Suntech report in the compressed binary form was passed over: this codec reads the text and the Universal binary forms. Set the device's report format to text.")
}

// binary reads a Universal binary report: type, 2-byte length, then the
// device ID (5 bytes, its decimal digits as hexadecimal), a 3-byte field
// mask and the fields the mask names, in the text form's order.
func (c *codec) binary(r *bufio.Reader, head []byte) (*track.Message, error) {
	n := 3 + int(binary.BigEndian.Uint16(head[1:3]))
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, io.ErrUnexpectedEOF
	}
	typ := b[0]
	if n < 11 || typ != 0x81 && typ != 0x82 {
		return nil, skipMsg("unknownMessage", hex.EncodeToString(b[:min(len(b), 16)]),
			"A Suntech binary frame this codec does not read was passed over.")
	}
	id := hex.EncodeToString(b[3:8])
	mask := uint32(b[8])<<16 | uint32(b[9])<<8 | uint32(b[10])
	has := func(bit uint) bool { return mask>>bit&1 == 1 }
	rd := &reader{b: b[11:]}
	st := map[string]any{}
	rec := track.Record{}
	if has(1) {
		st["model"] = fmt.Sprint(rd.u8())
	}
	if has(2) {
		st["firmware"] = fmt.Sprintf("%d.%d.%d", rd.u8(), rd.u8(), rd.u8())
	}
	if has(3) && rd.u8() == 0 {
		rec.History = true
	}
	var at time.Time
	if has(4) && has(5) {
		d := rd.take(6)
		at = time.Date(2000+int(d[0]), time.Month(d[1]), int(d[2]), int(d[3]), int(d[4]), int(d[5]), 0, time.UTC)
	}
	var cid, mcc, mnc, lac uint64
	if has(6) {
		cid = rd.u32()
	}
	if has(7) {
		mcc = rd.u16()
	}
	if has(8) {
		mnc = rd.u16()
	}
	if has(9) {
		lac = rd.u16()
	}
	if cid != 0 && mcc != 0 {
		rec.Network = &track.Network{Cells: []track.Cell{{MCC: int(mcc), MNC: int(mnc), LAC: int(lac), CID: int64(cid)}}}
	}
	if has(10) {
		st["gsm"] = int(rd.u8())
	}
	fix := &track.Fix{Time: at}
	var hasLat, hasLon bool
	if has(11) {
		fix.Lat, hasLat = signMagnitude(rd.u32())/1e6, true
	}
	if has(12) {
		fix.Lon, hasLon = signMagnitude(rd.u32())/1e6, true
	}
	if has(13) {
		fix.Speed = track.F(float64(rd.u16()) / 100)
	}
	if has(14) {
		fix.Heading = track.F(float64(rd.u16()) / 100)
	}
	if has(15) {
		fix.Sats = track.I(int(rd.u8()))
	}
	if has(16) {
		fix.Valid = rd.u8() > 0
	}
	if has(17) {
		in := rd.u8()
		st["ignition"] = in&1 == 1
		for i := 1; i <= 3; i++ {
			st[fmt.Sprintf("din%d", i)] = in>>i&1 == 1
		}
	}
	if has(18) {
		out := rd.u8()
		st["dout1"], st["dout2"] = out&1 == 1, out>>1&1 == 1
	}
	alertID := -1
	if has(19) {
		alertID = int(rd.u8())
		if typ == 0x82 {
			st["alertId"] = alertID
			alertOf(&rec, fmt.Sprint(alertID))
		} else {
			st["mode"] = alertID
		}
	}
	if has(20) {
		v := rd.u16()
		if typ == 0x82 {
			st["alertModifier"] = fmt.Sprint(v)
		}
	}
	// Alert 59 (a driver identification) carries the 8-byte driver ID.
	if has(21) && typ == 0x82 && alertID == 59 {
		st["driverId"] = hex.EncodeToString(rd.take(8))
	}
	if rd.err != nil {
		return nil, skipMsg("badField", hex.EncodeToString(b[:min(len(b), 16)]), "A Suntech binary report shorter than its field mask was passed over.")
	}
	if hasLat && hasLon && !at.IsZero() {
		rec.Fix = fix
		rec.Time = at
	}
	rec.Status = st
	c.learn(true, "")
	kind := "normal"
	if rec.History {
		kind = "history"
	}
	return &track.Message{IMEI: id, Kind: kind, Records: []track.Record{rec}}, nil
}

// signMagnitude reads a 32-bit sign-and-magnitude number (the top bit is
// the sign).
func signMagnitude(v uint64) float64 {
	m := float64(v & 0x7FFFFFFF)
	if v&0x80000000 != 0 {
		return -m
	}
	return m
}

type reader struct {
	b   []byte
	err error
}

func (r *reader) take(n int) []byte {
	if r.err != nil || len(r.b) < n {
		r.err = errors.New("suntech: binary report truncated")
		return make([]byte, n)
	}
	v := r.b[:n]
	r.b = r.b[n:]
	return v
}

func (r *reader) u8() uint64  { return uint64(r.take(1)[0]) }
func (r *reader) u16() uint64 { return uint64(binary.BigEndian.Uint16(r.take(2))) }
func (r *reader) u32() uint64 { return uint64(binary.BigEndian.Uint32(r.take(4))) }
