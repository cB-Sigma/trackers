package gt06

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/cB-Sigma/trackers/track"
)

// Cell and WiFi frames. Layouts (our reading of the Concox tables, checked
// against the frames quoted in Traccar's tests, Apache-2.0, see NOTICE):
//
//	0x28 0x2E 0x24 0x18 0x2C: date-time (6, binary, device clock), MCC (2;
//	  bit 15 set means a two-byte MNC follows), MNC (1 or 2), seven cells of
//	  LAC (2), cell ID (3) and signal (1, the magnitude of dBm; LAC 0 marks
//	  an empty slot), timing advance (1, 0xFF unknown); then for 0x2C (and
//	  0x18 when present) a WiFi count (1) and per access point MAC (6) and
//	  signal (1, magnitude of dBm). The rest (language) is ignored.
//	0x69 0x17: 0x7878, access point count (1, in place of the length),
//	  protocol, date-time (6, BCD), per access point MAC (6) and signal (1),
//	  cell count (1), MCC (2), MNC (1), per cell LAC (2), cell ID (2) and a
//	  signal level (1, not in dBm, kept out of the lookup), 0x0D0A.

const lbsCells = 7

// errShortLBS: an LBS frame shorter than the standard layout (vendor
// variants of 0x24 use other layouts) is skipped, not fatal.
var errShortLBS = track.ErrSkip

func (c *codec) date(dt []byte) time.Time {
	return time.Date(2000+int(dt[0]), time.Month(dt[1]), int(dt[2]), int(dt[3]), int(dt[4]), int(dt[5]), 0, c.cfg.loc)
}

func mac(b []byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5])
}

func dBm(b byte) *int {
	v := -int(b)
	return &v
}

// lbs decodes the multi-cell frames (and 0x2C's access points).
func (c *codec) lbs(proto byte, b []byte) (*track.Record, error) {
	if len(b) < 9 {
		return nil, errShortLBS
	}
	t := c.date(b[:6])
	mcc := int(binary.BigEndian.Uint16(b[6:8]))
	var mnc, p int
	if mcc&0x8000 != 0 {
		if len(b) < 10 {
			return nil, errShortLBS
		}
		mcc &= 0x7FFF
		mnc, p = int(binary.BigEndian.Uint16(b[8:10])), 10
	} else {
		mnc, p = int(b[8]), 9
	}
	if len(b) < p+lbsCells*6+1 {
		return nil, errShortLBS
	}
	n := &track.Network{}
	for range lbsCells {
		lac := int(binary.BigEndian.Uint16(b[p:]))
		cid := int64(b[p+2])<<16 | int64(b[p+3])<<8 | int64(b[p+4])
		if lac != 0 {
			n.Cells = append(n.Cells, track.Cell{MCC: mcc, MNC: mnc, LAC: lac, CID: cid, RSSI: dBm(b[p+5])})
		}
		p += 6
	}
	if ta := int(b[p]); ta != 0xFF {
		n.TA = &ta
	}
	p++
	if (proto == PLBSWiFi || proto == PLBSExtend) && p < len(b) {
		cnt := int(b[p])
		p++
		if p+cnt*7 > len(b) {
			if proto == PLBSWiFi {
				return nil, fmt.Errorf("gt06: 0x2C frame announces %d access points but is too short", cnt)
			}
			cnt = 0 // 0x18 without an access point list
		}
		for range cnt {
			n.WiFi = append(n.WiFi, track.WiFiAP{MAC: mac(b[p : p+6]), RSSI: dBm(b[p+6])})
			p += 7
		}
	}
	return &track.Record{Time: t, Network: n}, nil
}

func bcd(b byte) (int, bool) {
	hi, lo := int(b>>4), int(b&0x0F)
	return hi*10 + lo, hi < 10 && lo < 10
}

// wifi decodes a 0x69 / 0x17 frame (content as readWiFiFrame kept it).
func (c *codec) wifi(f *Frame) (*track.Record, error) {
	b := f.Content
	var dt [6]int
	for i := range dt {
		v, ok := bcd(b[i])
		if !ok {
			return nil, errors.New("gt06: WiFi frame time is not BCD")
		}
		dt[i] = v
	}
	t := time.Date(2000+dt[0], time.Month(dt[1]), dt[2], dt[3], dt[4], dt[5], 0, c.cfg.loc)
	n := &track.Network{}
	p := 6
	for range f.Count {
		n.WiFi = append(n.WiFi, track.WiFiAP{MAC: mac(b[p : p+6]), RSSI: dBm(b[p+6])})
		p += 7
	}
	cells := int(b[p])
	mcc, mnc := int(binary.BigEndian.Uint16(b[p+1:])), int(b[p+3])
	p += 4
	for range cells {
		lac, cid := int(binary.BigEndian.Uint16(b[p:])), int64(binary.BigEndian.Uint16(b[p+2:]))
		if lac != 0 {
			n.Cells = append(n.Cells, track.Cell{MCC: mcc, MNC: mnc, LAC: lac, CID: cid})
		}
		p += 5
	}
	return &track.Record{Time: t, Network: n}, nil
}

// readWiFiFrame reads the rest of a count-in-header WiFi frame; the 0x7878
// and the count byte n are already read and the protocol byte is next.
func readWiFiFrame(r *bufio.Reader, n int, fromServer bool) (*Frame, error) {
	proto, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	var body []byte
	read := func(k int) ([]byte, error) {
		s := make([]byte, k)
		if _, err := io.ReadFull(r, s); err != nil {
			return nil, err
		}
		body = append(body, s...)
		return s, nil
	}
	if fromServer {
		if _, err := read(6); err != nil {
			return nil, err
		}
	} else {
		if _, err := read(6 + 7*n); err != nil {
			return nil, err
		}
		hd, err := read(4) // cell count, MCC, MNC
		if err != nil {
			return nil, err
		}
		if _, err := read(5 * int(hd[0])); err != nil {
			return nil, err
		}
	}
	var end [2]byte
	if _, err := io.ReadFull(r, end[:]); err != nil {
		return nil, err
	}
	if end[0] != 0x0D || end[1] != 0x0A {
		return nil, fmt.Errorf("gt06: WiFi frame 0x%02X does not end with 0D0A", proto)
	}
	return &Frame{Protocol: proto, Content: body, Count: n, CountHeader: true}, nil
}

// WiFiAck is the answer to a 0x69 / 0x17 frame: 0x7878 00, the protocol,
// the frame's six time bytes, 0x0D0A.
func WiFiAck(proto byte, dt []byte) []byte {
	b := []byte{0x78, 0x78, 0x00, proto}
	b = append(b, dt...)
	return append(b, 0x0D, 0x0A)
}

// WiFiFrame builds a 0x69 / 0x17 frame (for simulators): BCD time, access
// points as (MAC, signal magnitude), cells as (LAC, cell ID, level).
func WiFiFrame(proto byte, t time.Time, aps [][7]byte, mcc uint16, mnc byte, cells [][5]byte) []byte {
	toBCD := func(v int) byte { return byte(v/10<<4 | v%10) }
	b := []byte{0x78, 0x78, byte(len(aps)), proto,
		toBCD(t.Year() - 2000), toBCD(int(t.Month())), toBCD(t.Day()), toBCD(t.Hour()), toBCD(t.Minute()), toBCD(t.Second())}
	for _, a := range aps {
		b = append(b, a[:]...)
	}
	b = append(b, byte(len(cells)))
	b = binary.BigEndian.AppendUint16(b, mcc)
	b = append(b, mnc)
	for _, c := range cells {
		b = append(b, c[:]...)
	}
	return append(b, 0x0D, 0x0A)
}
