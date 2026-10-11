// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package h02_test

import (
	"testing"
	"time"
)

// The Cantrack A/1 document's "Y model" binary record (section D): 'Y',
// two analog inputs, a reserved byte, then time, date, position, speed,
// course and status as in the '$' record, a user alarm flag, a reserved
// byte and a record number; no device id, so it follows a frame that
// named the device.
const yDoc = "5906410400001533281008152240563200113583509e003000e7e7fbffff0009"

func TestYModelRecord(t *testing.T) {
	ms, skips := decode(t, "", cV1, hx(yDoc), cHTBT)
	if len(ms) != 3 || len(skips) != 0 {
		t.Fatalf("decoded %d, skipped %v", len(ms), skips)
	}
	m := ms[1]
	if m.IMEI != "865205030330012" || m.Login || len(m.Records) != 1 {
		t.Fatalf("Y %+v", m)
	}
	r := m.Records[0]
	f := r.Fix
	if f == nil || f.Time != time.Date(2015, 8, 10, 15, 33, 28, 0, time.UTC) || !f.Valid || !near(f.Lat, 22+40.5632/60) || !near(f.Lon, 113+58.3509/60) ||
		*f.Speed != 5.56 || *f.Heading != 0 {
		t.Fatalf("Y fix %+v", f)
	}
	if r.Status["analog1"] != 0x0641 || r.Status["analog2"] != 0x0400 || r.Status["recordNumber"] != 9 || r.Status["statusWord"] != "E7E7FBFF" {
		t.Fatalf("Y status %v", r.Status)
	}
	// Before any frame names the device, a Y record is passed over.
	ms, skips = decode(t, "", hx(yDoc), cV1)
	if len(ms) != 2 || ms[0] != nil || len(skips) != 1 || ms[1] == nil {
		t.Fatalf("Y first: %v %v", ms, skips)
	}
	// A 'Y' that does not start a record (noise) does not swallow the next frame.
	ms, skips = decode(t, "", "Y\r\n", cV1, "Yes\r\n", cHTBT)
	if len(ms) != 2 || len(skips) != 0 || ms[0].IMEI != "865205030330012" {
		t.Fatalf("Y noise: %v %v", ms, skips)
	}
}
