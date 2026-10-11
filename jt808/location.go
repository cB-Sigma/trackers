package jt808

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/cB-Sigma/trackers/track"
)

// Location is a decoded location body (0x0200, and inside 0x0201, 0x0500
// and 0x0704): the 28-byte basic block and the additional items.
type Location struct {
	Alarm, Status uint32
	Fix           track.Fix
	// Items are the additional items by ID (the last one wins when an ID
	// repeats).
	Items map[byte][]byte
}

// Status bits (JT/T 808-2013 table 25).
const (
	StACC        = 1 << 0
	StPositioned = 1 << 1
	StSouth      = 1 << 2
	StWest       = 1 << 3
	StStopped    = 1 << 4
	StFuelCut    = 1 << 10
	StCircuitCut = 1 << 11
	StDoorLocked = 1 << 12
	stDoors      = 0x1F << 13
)

// alarmTypes maps alarm flag bits (JT/T 808-2013 table 24) to alert types.
var alarmTypes = map[int]string{
	0:  "emergency",
	1:  "over-speed",
	2:  "fatigue-driving",
	3:  "danger-warning",
	4:  "gnss-module-fault",
	5:  "gnss-antenna-cut",
	6:  "gnss-antenna-short",
	7:  "low-battery", // main power undervoltage
	8:  "main-power-removed",
	9:  "display-fault",
	10: "tts-fault",
	11: "camera-fault",
	12: "ic-card-fault",
	13: "over-speed-warning",
	14: "fatigue-warning",
	18: "driving-time-exceeded",
	19: "parking-timeout",
	20: "geofence",
	21: "route",
	22: "route-time",
	23: "route-deviation",
	24: "vss-fault",
	25: "fuel-abnormal",
	26: "theft",
	27: "illegal-ignition",
	28: "towing",
	29: "impact",
	30: "rollover",
	31: "door-open",
}

// ParseLocation reads a location body in zone loc (the device's clock).
func ParseLocation(b []byte, loc *time.Location) (*Location, error) {
	if len(b) < 28 {
		return nil, fmt.Errorf("a location body is 28 bytes or more, this one %d", len(b))
	}
	l := &Location{Alarm: binary.BigEndian.Uint32(b[0:4]), Status: binary.BigEndian.Uint32(b[4:8]), Items: map[byte][]byte{}}
	f := &l.Fix
	f.Lat = float64(binary.BigEndian.Uint32(b[8:12])) / 1e6
	f.Lon = float64(binary.BigEndian.Uint32(b[12:16])) / 1e6
	if l.Status&StSouth != 0 {
		f.Lat = -f.Lat
	}
	if l.Status&StWest != 0 {
		f.Lon = -f.Lon
	}
	f.Valid = l.Status&StPositioned != 0
	alt := float64(int16(binary.BigEndian.Uint16(b[16:18])))
	f.Alt = &alt
	spd := float64(binary.BigEndian.Uint16(b[18:20])) / 10
	f.Speed = &spd
	hdg := float64(binary.BigEndian.Uint16(b[20:22]))
	f.Heading = &hdg
	if v, ok := bcdFields(b[22:28]); ok && v[1] >= 1 && v[1] <= 12 && v[2] >= 1 {
		f.Time = time.Date(2000+v[0], time.Month(v[1]), v[2], v[3], v[4], v[5], 0, loc).UTC()
	}
	rest := b[28:]
	for len(rest) >= 2 {
		id, n := rest[0], int(rest[1])
		if len(rest) < 2+n {
			break // a truncated last item is dropped
		}
		l.Items[id] = rest[2 : 2+n]
		rest = rest[2+n:]
	}
	if s := l.Items[0x31]; len(s) == 1 {
		f.Sats = track.I(int(s[0]))
	}
	return l, nil
}

// StatusValues are the status values of a location.
func (l *Location) StatusValues() map[string]any {
	st := map[string]any{
		"ignition":   l.Status&StACC != 0,
		"moving":     l.Status&StStopped == 0,
		"fuelCut":    l.Status&StFuelCut != 0,
		"circuitCut": l.Status&StCircuitCut != 0,
		"doorLocked": l.Status&StDoorLocked != 0,
		"doorOpen":   l.Status&stDoors != 0,
		"alarmFlags": l.Alarm,
	}
	for id, v := range l.Items {
		switch {
		case id == 0x01 && len(v) == 4:
			st["odometer"] = float64(binary.BigEndian.Uint32(v)) / 10 // km
		case id == 0x02 && len(v) == 2:
			st["fuel"] = float64(binary.BigEndian.Uint16(v)) / 10 // litres
		case id == 0x03 && len(v) == 2:
			st["tachographSpeed"] = float64(binary.BigEndian.Uint16(v)) / 10 // km/h
		case id == 0x25 && len(v) == 4:
			st["vehicleSignals"] = binary.BigEndian.Uint32(v)
		case id == 0x2A && len(v) == 2:
			st["ioStatus"] = binary.BigEndian.Uint16(v)
		case id == 0x2B && len(v) == 4:
			st["adc0"] = int(binary.BigEndian.Uint16(v[2:4]))
			st["adc1"] = int(binary.BigEndian.Uint16(v[0:2]))
		case id == 0x30 && len(v) == 1:
			st["gsm"] = int(v[0])
		case id == 0x31, id == 0x04, id == 0x11, id == 0x12, id == 0x13:
			// Satellites go in the fix; the alarm details in the alerts.
		case id >= 0x64 && id <= 0x67 && safetyOK(id, v, st):
			// Active safety items (safety.go).
		default:
			// An item this codec does not interpret (vendor items 0xE1
			// to 0xFF among them) is kept as hexadecimal.
			st[fmt.Sprintf("item0x%02X", id)] = fmt.Sprintf("%X", v)
		}
	}
	return st
}

func safetyOK(id byte, v []byte, st map[string]any) bool {
	_, ok := safetyItem(id, v, st)
	return ok
}

// alertsFor are the alerts of the alarm bits set in now but not in prev.
func (l *Location) alertsFor(prev uint32) []track.Alert {
	var out []track.Alert
	for bit := range 32 {
		m := uint32(1) << bit
		if l.Alarm&m == 0 || prev&m != 0 {
			continue
		}
		typ, ok := alarmTypes[bit]
		if !ok {
			typ = fmt.Sprintf("alarm-bit%d", bit)
		}
		if bit == 20 || bit == 21 {
			// Area and route alarms name the direction in item 0x12.
			if v := l.Items[0x12]; len(v) == 6 {
				dir := "enter"
				if v[5] == 1 {
					dir = "exit"
				}
				if bit == 20 {
					typ = "geofence-" + dir
				} else {
					typ = "route-" + dir
				}
			}
		}
		out = append(out, track.NewAlert(typ, fmt.Sprintf("bit%d", bit)))
	}
	return out
}
