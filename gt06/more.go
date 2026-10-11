// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package gt06

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode/utf16"

	"github.com/cB-Sigma/trackers/track"
)

// Further protocol numbers. Layouts from the Concox "GPS Tracker
// Communication Protocol" for the GK310 (V1.0.3), checked against the
// device frames quoted in Traccar's GT06 tests (Apache-2.0, see NOTICE);
// 0x32, 0x33 and 0x9B, which no Concox document we could find describes,
// from the layout those frames show.
//
//	0x10  GPS only: date-time and the GPS block (as 0x12 without the cell)
//	0x19  alarm with a cell and no GPS: MCC, MNC, LAC (2), cell ID (3),
//	      terminal information, voltage level, GSM level, alarm, language
//	0xA5  the same with a 4G cell: LAC (4), cell ID (8)
//	0x23  heartbeat: terminal information, voltage (2, hundredths of a
//	      volt), GSM level, language (2); answered
//	0x27  alarm with several fences: as 0x26, then a fence number
//	0xA3  0xA4: 0x26 and 0x27 whose LBS block holds a 4G cell
//	0x2A  address request: date-time, GPS block, phone number (21, ASCII),
//	      language (2)
//	0x17  (with a length byte) the same with a cell in place of the GPS
//	      block; 0xA7 with a 4G cell. Not answered: the address is the
//	      server's to look up and send with AddressReply (0x97).
//	0xA0  4G location: date-time, GPS block, MCC, MNC, LAC (4), cell ID
//	      (8), ACC, upload mode, re-upload flag, mileage (4, optional)
//	0xA1  4G cells: date-time, MCC, MNC, seven cells of LAC (4), cell ID
//	      (8) and signal (1), timing advance, language (2); answered
//	0xA2  0xA1's cells, then a WiFi count and per access point MAC (6)
//	      and signal (1); not answered
//	0x9B  data of an external device passed through: device type (1),
//	      data (text when printable, else hexadecimal); not answered
//	0x32  0x33 (0x7979 frames): date-time, GPS length and block, LBS
//	      length and cell, signal, more cells (length, then LAC 2, cell ID
//	      3, signal 1 each), WiFi (length, then MAC 6 and signal 1 each),
//	      status (0x33: A0 armed, A1 disarmed, A2 A3 low battery, A4 alarm,
//	      A5 door), a reserved block (length); answered in a 0x7979 frame.
//	      In 0x7878 frames the same numbers are other devices' layouts and
//	      are passed over.
const (
	PGPS           = 0x10 // GPS only
	PLBSAlarm      = 0x19 // alarm with a cell, no GPS
	PHeartbeat     = 0x23 // heartbeat with the voltage
	PAlarmFences   = 0x27 // alarm with a fence number
	PGPSAddress    = 0x2A // address request with a position
	PLBSAddress    = 0x17 // address request with a cell (a frame with a length byte, unlike PWiFi)
	PExtGPS        = 0x32 // 0x7979 location of variable blocks
	PExtAlarm      = 0x33 // 0x7979 alarm of variable blocks
	PAddressReply  = 0x97 // the server's address answer (English, UTF-16)
	PTransparent   = 0x9B // external device data passed through
	P4GLocation    = 0xA0 // location with a 4G cell
	P4GLBSMulti    = 0xA1 // 4G cells
	P4GLBSWiFi     = 0xA2 // 4G cells and WiFi access points
	P4GAlarm       = 0xA3 // 0x26 with a 4G cell
	P4GAlarmFences = 0xA4 // 0x27 with a 4G cell
	P4GLBSAlarm    = 0xA5 // 0x19 with a 4G cell
	P4GLBSAddress  = 0xA7 // 0x17 with a 4G cell
)

// cellAt reads MCC, MNC (two bytes when the MCC's top bit is set), LAC and
// cell ID from b; wide is the 4G form (LAC 4, cell ID 8). It returns the
// cell and the bytes read.
func cellAt(b []byte, wide bool) (track.Cell, int, bool) {
	if len(b) < 3 {
		return track.Cell{}, 0, false
	}
	mcc := int(binary.BigEndian.Uint16(b))
	var mnc, p int
	if mcc&0x8000 != 0 {
		mcc &= 0x7FFF
		if len(b) < 4 {
			return track.Cell{}, 0, false
		}
		mnc, p = int(binary.BigEndian.Uint16(b[2:])), 4
	} else {
		mnc, p = int(b[2]), 3
	}
	c := track.Cell{MCC: mcc, MNC: mnc}
	if wide {
		if len(b) < p+12 {
			return c, 0, false
		}
		c.LAC = int(binary.BigEndian.Uint32(b[p:]))
		c.CID = int64(binary.BigEndian.Uint64(b[p+4:]) & 0x7FFFFFFFFFFFFFFF)
		return c, p + 12, true
	}
	if len(b) < p+5 {
		return c, 0, false
	}
	c.LAC = int(binary.BigEndian.Uint16(b[p:]))
	c.CID = int64(b[p+2])<<16 | int64(b[p+3])<<8 | int64(b[p+4])
	return c, p + 5, true
}

// lbsBlock reads the cell of an LBS block (without its length byte),
// whose size tells the 4G form from the 2G one. An empty cell is not one.
func lbsBlock(b []byte) (track.Cell, bool) {
	mncW := 1
	if len(b) >= 2 && b[0]&0x80 != 0 {
		mncW = 2
	}
	c, _, ok := cellAt(b, len(b) >= 2+mncW+12)
	return c, ok && (c.LAC != 0 || c.CID != 0)
}

func oneCell(c track.Cell) *track.Network {
	if c.LAC == 0 && c.CID == 0 {
		return nil
	}
	return &track.Network{Cells: []track.Cell{c}}
}

// alarmStatus reads terminal information, voltage level, GSM level and
// the alarm code of an alarm frame into rec.
func (c *codec) alarmStatus(rec *track.Record, rest []byte) {
	if len(rest) < 4 {
		return
	}
	rec.Status = terminalInfo(rest[0])
	rec.Status["batteryLevel"], rec.Status["gsm"] = int(rest[1]), int(rest[2])
	if a, ok := c.cfg.alarms[rest[3]]; ok {
		if a.Code == "" {
			a.Code = fmt.Sprintf("0x%02X", rest[3])
		}
		rec.Alerts = append(rec.Alerts, a)
	} else if rest[3] != 0 {
		rec.Alerts = append(rec.Alerts, track.Alert{Type: fmt.Sprintf("alarm-0x%02X", rest[3]), Severity: track.Minor, Code: fmt.Sprintf("0x%02X", rest[3])})
	}
}

// phone reads a 21-byte phone number field (ASCII, padded with zeros).
func phone(b []byte) string {
	return strings.TrimSpace(strings.TrimRight(string(b), "\x00"))
}

func printable(b []byte) bool {
	for _, x := range b {
		if (x < 0x20 || x > 0x7E) && x != '\r' && x != '\n' && x != '\t' {
			return false
		}
	}
	return len(b) > 0
}

// more decodes the further protocol numbers; ok is false for a number it
// does not read either.
func (c *codec) more(f *Frame, m *track.Message) (bool, error) {
	b := f.Content
	ack := func() { m.Reply = Encode(f.Protocol, nil, f.Serial) }
	switch f.Protocol {
	case PGPS:
		if len(b) < 18 {
			return true, short("GPS", f.Protocol, len(b))
		}
		m.Records = []track.Record{{Fix: c.gps(b[:6], b[6:18]), Status: map[string]any{}}}
		if c.cfg.ackLoc {
			ack()
		}
	case PHeartbeat:
		if len(b) < 4 {
			return true, short("heartbeat", f.Protocol, len(b))
		}
		st := terminalInfo(b[0])
		st["batteryVoltage"] = float64(binary.BigEndian.Uint16(b[1:3])) / 100
		st["gsm"] = int(b[3])
		m.Records = []track.Record{{Status: st, Alerts: infoAlerts(b[0])}}
		ack()
	case PLBSAlarm, P4GLBSAlarm:
		cell, n, ok := cellAt(b, f.Protocol == P4GLBSAlarm)
		if !ok || len(b) < n+4 {
			return true, short("cell alarm", f.Protocol, len(b))
		}
		rec := track.Record{Network: oneCell(cell)}
		c.alarmStatus(&rec, b[n:])
		m.Records = []track.Record{rec}
		ack()
	case PGPSAddress:
		if len(b) < 18+21 {
			return true, short("address request", f.Protocol, len(b))
		}
		m.Records = []track.Record{{Fix: c.gps(b[:6], b[6:18]),
			Status: map[string]any{"addressRequest": true, "phone": phone(b[18:39])}}}
	case P4GLBSAddress:
		return true, c.addressCell(f, m)
	case P4GLocation:
		if len(b) < 18 {
			return true, short("location", f.Protocol, len(b))
		}
		rec := track.Record{Fix: c.gps(b[:6], b[6:18]), Status: map[string]any{}}
		cell, n, ok := cellAt(b[18:], true)
		if ok {
			rec.Network = oneCell(cell)
			rest := b[18+n:]
			if len(rest) >= 3 {
				rec.Status["ignition"] = rest[0] == 1
				rec.Status["uploadMode"] = int(rest[1])
				rec.History = rest[2] == 1
			}
			if len(rest) >= 7 {
				rec.Status["mileage"] = float64(binary.BigEndian.Uint32(rest[3:7])) / 100
			}
		}
		m.Records = []track.Record{rec}
		if c.cfg.ackLoc {
			ack()
		}
	case P4GLBSMulti, P4GLBSWiFi:
		rec, err := c.lbs4G(f.Protocol, b)
		if err != nil {
			return true, err
		}
		m.Records = []track.Record{*rec}
		if f.Protocol == P4GLBSMulti {
			ack()
		}
	case PTransparent:
		if len(b) < 1 {
			return true, short("transparent", f.Protocol, len(b))
		}
		st := map[string]any{"externalDevice": int(b[0])}
		if d := b[1:]; printable(d) {
			st["externalData"] = strings.TrimSpace(string(d))
		} else {
			st["externalData"] = fmt.Sprintf("%X", d)
		}
		m.Records = []track.Record{{Status: st}}
	case PExtGPS, PExtAlarm:
		if !f.Ext {
			return false, nil
		}
		rec, err := c.extended(f)
		if err != nil {
			return true, err
		}
		m.Records = []track.Record{*rec}
		m.Reply = encodeExt(f.Protocol, nil, f.Serial)
	default:
		return false, nil
	}
	return true, nil
}

// addressRequest decodes a 0x17 frame with a length byte.
func (c *codec) addressRequest(f *Frame, m *track.Message) (*track.Message, error) {
	if err := c.addressCell(f, m); err != nil {
		return nil, err
	}
	return m, nil
}

func (c *codec) addressCell(f *Frame, m *track.Message) error {
	cell, n, ok := cellAt(f.Content, f.Protocol == P4GLBSAddress)
	if !ok || len(f.Content) < n+21 {
		return short("address request", f.Protocol, len(f.Content))
	}
	m.Records = []track.Record{{Network: oneCell(cell),
		Status: map[string]any{"addressRequest": true, "phone": phone(f.Content[n : n+21])}}}
	return nil
}

// lbs4G decodes 0xA1 and 0xA2.
func (c *codec) lbs4G(proto byte, b []byte) (*track.Record, error) {
	if len(b) < 9 {
		return nil, errShortLBS
	}
	t := c.date(b[:6])
	head, p, ok := cellAt(b[6:], false)
	if !ok {
		return nil, errShortLBS
	}
	p = 6 + p - 5 // MCC and MNC only; the cells follow
	if len(b) < p+lbsCells*13+1 {
		return nil, short("4G cell", proto, len(b))
	}
	n := &track.Network{}
	for range lbsCells {
		lac := int(binary.BigEndian.Uint32(b[p:]))
		cid := int64(binary.BigEndian.Uint64(b[p+4:]) & 0x7FFFFFFFFFFFFFFF)
		if lac != 0 || cid != 0 {
			n.Cells = append(n.Cells, track.Cell{MCC: head.MCC, MNC: head.MNC, LAC: lac, CID: cid, RSSI: dBm(b[p+12])})
		}
		p += 13
	}
	if ta := int(b[p]); ta != 0xFF {
		n.TA = &ta
	}
	p++
	if proto == P4GLBSWiFi {
		if p >= len(b) {
			return nil, short("4G WiFi", proto, len(b))
		}
		cnt := int(b[p])
		p++
		if p+cnt*7 > len(b) {
			return nil, short("4G WiFi", proto, len(b))
		}
		for range cnt {
			if mc := b[p : p+6]; string(mc) != "\x00\x00\x00\x00\x00\x00" {
				n.WiFi = append(n.WiFi, track.WiFiAP{MAC: mac(mc), RSSI: dBm(b[p+6])})
			}
			p += 7
		}
	}
	return &track.Record{Time: t, Network: n}, nil
}

// extended decodes the 0x7979 0x32 and 0x33 frames.
func (c *codec) extended(f *Frame) (*track.Record, error) {
	b := f.Content
	bad := func() error { return short("extended location", f.Protocol, len(b)) }
	if len(b) < 8 {
		return nil, bad()
	}
	rec := &track.Record{Time: c.date(b[:6]), Status: map[string]any{}}
	p := 6
	if gl := int(b[p]); gl > 0 {
		if gl < 12 || len(b) < p+1+gl {
			return nil, bad()
		}
		rec.Fix = c.gps(b[:6], b[p+1:p+13])
		p += 1 + gl
	} else {
		p++
	}
	// The LBS block: its length counts itself; a signal byte follows.
	if p >= len(b) {
		return nil, bad()
	}
	n := &track.Network{}
	var head track.Cell
	if ll := int(b[p]); ll > 0 {
		if len(b) < p+ll+1 {
			return nil, bad()
		}
		cell, _, ok := cellAt(b[p+1:p+ll], false)
		if ok {
			head = cell
			if cell.LAC != 0 || cell.CID != 0 {
				n.Cells = append(n.Cells, cell)
			}
		}
		rec.Status["gsm"] = int(b[p+ll])
		p += ll + 1
	} else {
		p++
	}
	// More cells, then access points, each block after its length.
	if p >= len(b) {
		return nil, bad()
	}
	if cl := int(b[p]); p+1+cl <= len(b) {
		for q := p + 1; q+6 <= p+1+cl; q += 6 {
			lac := int(binary.BigEndian.Uint16(b[q:]))
			cid := int64(b[q+2])<<16 | int64(b[q+3])<<8 | int64(b[q+4])
			if lac != 0 || cid != 0 {
				n.Cells = append(n.Cells, track.Cell{MCC: head.MCC, MNC: head.MNC, LAC: lac, CID: cid})
			}
		}
		p += 1 + cl
	} else {
		return nil, bad()
	}
	if p >= len(b) {
		return nil, bad()
	}
	if wl := int(b[p]); p+1+wl <= len(b) {
		if wl%7 == 0 {
			for q := p + 1; q < p+1+wl; q += 7 {
				n.WiFi = append(n.WiFi, track.WiFiAP{MAC: mac(b[q : q+6]), RSSI: dBm(b[q+6])})
			}
		}
		p += 1 + wl
	} else {
		return nil, bad()
	}
	if len(n.Cells) > 0 || len(n.WiFi) > 0 {
		rec.Network = n
	}
	if p < len(b) {
		st := b[p]
		rec.Status["deviceStatus"] = int(st)
		if f.Protocol == PExtAlarm {
			switch st {
			case 0xA0:
				rec.Status["armed"] = true
			case 0xA1:
				rec.Status["armed"] = false
			case 0xA2, 0xA3:
				rec.Alerts = append(rec.Alerts, track.NewAlert("low-battery", fmt.Sprintf("0x%02X", st)))
			case 0xA4:
				rec.Alerts = append(rec.Alerts, track.NewAlert("device-alarm", "0xA4"))
			case 0xA5:
				rec.Alerts = append(rec.Alerts, track.NewAlert("door-open", "0xA5"))
			}
		}
	}
	return rec, nil
}

// encodeExt builds a 0x7979 frame (two length bytes) whatever its size.
func encodeExt(protocol byte, content []byte, serial uint16) []byte {
	n := 1 + len(content) + 4
	b := []byte{0x79, 0x79, byte(n >> 8), byte(n), protocol}
	b = append(b, content...)
	b = binary.BigEndian.AppendUint16(b, serial)
	b = binary.BigEndian.AppendUint16(b, track.CRCITU(b[2:]))
	return append(b, 0x0D, 0x0A)
}

// AddressReply builds the server's English address answer (0x97, in a
// 0x7979 frame) to an address request (0x2A, 0x17, 0xA7), with the phone
// number the request carried, or to an alarm, with phoneNumber "": a
// two-byte length (server flag and what follows it, as the GK310
// document's example frames count it), the server flag, "ADDRESS" (an
// alarm: "ALARMSMS"), "&&", the address in UTF-16, "&&", the phone number
// padded with zeros to 21 bytes (an alarm: "0"), "##".
func AddressReply(flag uint32, address, phoneNumber string, serial uint16) []byte {
	code := "ADDRESS"
	if phoneNumber == "" {
		code, phoneNumber = "ALARMSMS", "0"
	}
	var body []byte
	body = append(body, code...)
	body = append(body, "&&"...)
	for _, u := range utf16.Encode([]rune(address)) {
		body = binary.BigEndian.AppendUint16(body, u)
	}
	body = append(body, "&&"...)
	ph := make([]byte, 21)
	copy(ph, phoneNumber)
	body = append(body, ph...)
	body = append(body, "##"...)
	c := binary.BigEndian.AppendUint16(nil, uint16(4+len(body)))
	c = binary.BigEndian.AppendUint32(c, flag)
	c = append(c, body...)
	return encodeExt(PAddressReply, c, serial)
}
