package ais140

import (
	"fmt"
	"strconv"
)

// DeviceID is the unique VLT device identifier of AIS-140 Amendment 3
// clause 3.1.1.12 (item 9), stored with the IMEI: four letters or digits
// for the manufacturer, two for the model, one letter for the test agency
// that approved it, the month and year of manufacture (MMYY) and an
// eight-digit production serial number, nineteen characters in all. No
// packet carries it (F-186), so it is a device setting checked at load.
type DeviceID struct {
	Manufacturer, Model string
	TestAgency          byte
	Month, Year         int // Year is the two digits, 0 to 99
	Serial              string
}

// TestAgencies are the agency letters of the clause.
var TestAgencies = map[byte]string{
	'A': "Automotive Research Association of India",
	'C': "Central Institute of Road Transport",
	'I': "International Centre for Automotive Technology",
	'V': "Vehicle Research & Development Establishment",
	'F': "Central Farm Machinery Training & Testing Institute",
	'P': "Indian Institute of Petroleum",
	'G': "Global Automotive Research Centre",
	'N': "National Automotive Test Tracks",
	'R': "Northern Region Farm Machinery Training & Testing Institute",
}

func alnum(s string) bool {
	for i := 0; i < len(s); i++ {
		b := s[i]
		if !(b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z') {
			return false
		}
	}
	return true
}

// ParseDeviceID checks and splits a device ID.
func ParseDeviceID(s string) (DeviceID, error) {
	if len(s) != 19 {
		return DeviceID{}, fmt.Errorf("device ID %q has %d characters; AIS-140 3.1.1.12 has 19 (manufacturer 4, model 2, test agency 1, MMYY 4, serial 8)", s, len(s))
	}
	d := DeviceID{Manufacturer: s[0:4], Model: s[4:6], TestAgency: s[6], Serial: s[11:19]}
	if !alnum(d.Manufacturer) || !alnum(d.Model) {
		return DeviceID{}, fmt.Errorf("device ID %q: the manufacturer and model codes must be letters or digits", s)
	}
	if _, ok := TestAgencies[d.TestAgency]; !ok {
		return DeviceID{}, fmt.Errorf("device ID %q: %q is not a test agency letter (A, C, I, V, F, P, G, N, R)", s, d.TestAgency)
	}
	mm, yy := s[7:9], s[9:11]
	if !isDigits(mm) || !isDigits(yy) || !isDigits(d.Serial) {
		return DeviceID{}, fmt.Errorf("device ID %q: the month, year and serial number must be digits", s)
	}
	d.Month, _ = strconv.Atoi(mm)
	d.Year, _ = strconv.Atoi(yy)
	if d.Month < 1 || d.Month > 12 {
		return DeviceID{}, fmt.Errorf("device ID %q: month %s is not 01 to 12", s, mm)
	}
	return d, nil
}
