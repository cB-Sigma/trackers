package ais140

import (
	"strconv"
	"strings"

	"github.com/cB-Sigma/trackers/track"
)

// The layouts AIS-140 fixes since Amendment 3 (04/2026), which replaced
// "any sequence, any separator" with the tables' sequence and commas
// (item 15, clause 4.1). Field positions below count from the header (0)
// after the '$'; the clause and table of each layout is named. A packet
// whose markers are not where the table puts them (a vendor's variation)
// is read by the anchors instead (ais140.go auto).

// Data message, Table 4A(2) (item 17), with the trailer ID of the RFID
// variant (3.1.1.28, item 11). The table numbers its rows 1 to 57 but has
// no row 52; the sample packet confirms no field is missing (F-178).
var stdPVT = []string{
	"header", "vendor", "firmware", "packetType", "alertId", "packetStatus", "imei", "vehicle", "gpsFix", "date", "time",
	"lat", "latDir", "lon", "lonDir", "speed", "heading", "satellites", "altitude", "pdop", "hdop", "operator",
	"ignition", "mainPower", "mainVoltage", "batteryVoltage", "emergency", "tamper", "gsm", "mcc", "mnc", "lac", "cellId",
	"nmr1Signal", "nmr1Lac", "nmr1Cell", "nmr2Signal", "nmr2Lac", "nmr2Cell", "nmr3Signal", "nmr3Lac", "nmr3Cell",
	"nmr4Signal", "nmr4Lac", "nmr4Cell", "digitalInputs", "digitalOutputs", "frame", "analogInput1", "analogInput2",
	"deltaDistance", "otaResponse", "trailerId",
}

// stdPVTMin is the field count without the optional trailer ID.
const stdPVTMin = 52

// pvt reads a Table 4A(2) packet; ok is false when the markers are not in
// their places.
func pvt(tok []string) (map[string]string, bool) {
	tok = joinParens(tok, 51)
	if len(tok) < stdPVTMin || len(tok) > len(stdPVT) {
		return nil, false
	}
	if !imeiField(tok[6]) || (tok[12] != "N" && tok[12] != "S") || (tok[14] != "E" && tok[14] != "W") ||
		!strings.HasPrefix(tok[51], "(") {
		return nil, false
	}
	p := map[string]string{}
	for i, n := range stdPVT {
		if i < len(tok) {
			p[n] = tok[i]
		}
	}
	if len(tok) == len(stdPVT) {
		p["hasTrailer"] = "1"
	}
	return p, true
}

// joinParens puts back together a parenthesised field at index i that
// contains commas (an OTA response value may).
func joinParens(tok []string, i int) []string {
	if i >= len(tok) || !strings.HasPrefix(tok[i], "(") || strings.HasSuffix(tok[i], ")") {
		return tok
	}
	for j := i + 1; j < len(tok); j++ {
		if strings.HasSuffix(tok[j], ")") {
			out := append([]string(nil), tok[:i]...)
			out = append(out, strings.Join(tok[i:j+1], ","))
			return append(out, tok[j+1:]...)
		}
	}
	return tok
}

// Login message, Table 4A(1) (item 16): header, vehicle registration,
// IMEI, ICCID, firmware, protocol version, position.
func stdLogin(tok []string) (map[string]string, bool) {
	if len(tok) != 10 || !imeiField(tok[2]) || !isICCID(tok[3]) ||
		(tok[7] != "N" && tok[7] != "S") || (tok[9] != "E" && tok[9] != "W") {
		return nil, false
	}
	return map[string]string{"vehicle": tok[1], "imei": tok[2], "iccid": tok[3], "firmware": tok[4], "protocol": tok[5],
		"lat": tok[6], "latDir": tok[7], "lon": tok[8], "lonDir": tok[9]}, true
}

// isICCID: 19 or 20 characters, digits with an optional final F (the
// table's two samples), starting 89 (telecommunications, ITU-T E.118).
func isICCID(s string) bool {
	if len(s) < 19 || len(s) > 20 || !strings.HasPrefix(s, "89") {
		return false
	}
	body := s
	if last := s[len(s)-1]; last == 'F' || last == 'f' {
		body = s[:len(s)-1]
	}
	return isDigits(body)
}

// Health packet, Table 3B (item 14): header, vendor, firmware, IMEI, then
// the health fields (profile.healthFields, default the table's).
var stdHealthFields = []string{"batteryPercent", "lowBatteryThreshold", "memoryPercent", "updateRateIgnitionOn",
	"updateRateIgnitionOff", "digitalIO", "analogInput1", "analogInput2"}

// Emergency message by SMS, Table 4C ii) (item 20): header, EMR or SEM,
// IMEI, position, validity, speed, cell ID, LAC, date and time. Its
// position follows the IMEI directly, which tells it from Table 4C i).
func stdEmergencySMS(tok []string, im, a int) map[string]string {
	p := map[string]string{"imei": tok[im], "lat": tok[a], "latDir": tok[a+1], "lon": tok[a+2], "lonDir": tok[a+3],
		"gpsFix": at(tok, a+4), "speed": at(tok, a+5), "cellId": at(tok, a+6), "lac": at(tok, a+7), "sms": "1"}
	switch dt := at(tok, a+8); {
	case len(dt) == 14 && isDigits(dt): // the sample: DDMMYYYYhhmmss
		p["datetime"] = dt
	case len(dt) == 12 && isDigits(dt): // the description: DDMMYYhhmmss (F-183)
		p["date"], p["time"] = dt[:6], dt[6:]
	}
	for i := 0; i < im; i++ {
		if u := upper(tok[i]); u == "EMR" || u == "SEM" {
			p["packetType"] = u
		}
	}
	return p
}

// Activation and health check answers, Amendment 2 clause 8.4 Table-1:
// ACTVR or HCHKR, the request's random code, vendor, firmware, IMEI, alert
// ID, position, fix, "DDMMYYYY hhmmss", heading, speed, GSM strength, MCC,
// MNC, LAC, main power, ignition, battery voltage, frame number, vehicle
// mode.
func stdCheckReply(tok []string) (map[string]string, bool) {
	if len(tok) < 20 || !imeiField(tok[4]) || (tok[7] != "N" && tok[7] != "S") || (tok[9] != "E" && tok[9] != "W") {
		return nil, false
	}
	p := map[string]string{"replyKind": strings.TrimSuffix(upper(tok[0]), "R"), "replyCode": tok[1], "vendor": tok[2],
		"firmware": tok[3], "imei": tok[4], "alertId": tok[5], "lat": tok[6], "latDir": tok[7], "lon": tok[8], "lonDir": tok[9],
		"gpsFix": tok[10], "heading": at(tok, 12), "speed": at(tok, 13), "gsm": at(tok, 14), "mcc": at(tok, 15),
		"mnc": at(tok, 16), "lac": at(tok, 17), "mainPower": at(tok, 18), "ignition": at(tok, 19),
		"batteryVoltage": at(tok, 20), "frame": at(tok, 21), "vehicleMode": at(tok, 22)}
	if d, t, ok := strings.Cut(tok[11], " "); ok {
		p["date"], p["time"] = d, t
	} else if len(tok[11]) == 14 {
		p["datetime"] = tok[11]
	}
	return p, true
}

// network turns the serving and neighbour cells of a Table 4A(2) packet
// into a network report. LAC and cell ID are hexadecimal; the serving
// signal is 0 to 31 (converted to dBm as -113 + 2n). The neighbours'
// signal has no unit in the table and samples above 31 (F-180), so it is
// kept only as reported, in status.
func network(p map[string]string) (*track.Network, []any) {
	mcc, err1 := strconv.Atoi(p["mcc"])
	mnc, err2 := strconv.Atoi(p["mnc"])
	if err1 != nil || err2 != nil {
		return nil, nil
	}
	cell := func(lac, cid string) (track.Cell, bool) {
		l, e1 := strconv.ParseInt(lac, 16, 32)
		c, e2 := strconv.ParseInt(cid, 16, 64)
		if e1 != nil || e2 != nil || c == 0 {
			return track.Cell{}, false
		}
		return track.Cell{MCC: mcc, MNC: mnc, LAC: int(l), CID: c}, true
	}
	n := &track.Network{}
	if c, ok := cell(p["lac"], p["cellId"]); ok {
		if v, err := strconv.Atoi(p["gsm"]); err == nil && v >= 0 && v <= 31 {
			c.RSSI = track.I(-113 + 2*v)
		}
		n.Cells = append(n.Cells, c)
	}
	var nmr []any
	for i := 1; i <= 4; i++ {
		k := "nmr" + strconv.Itoa(i)
		lac, cid, sig := p[k+"Lac"], p[k+"Cell"], p[k+"Signal"]
		if c, ok := cell(lac, cid); ok {
			n.Cells = append(n.Cells, c)
			e := map[string]any{"lac": lac, "cellId": cid}
			if v, err := strconv.Atoi(sig); err == nil {
				e["signal"] = v
			}
			nmr = append(nmr, e)
		}
	}
	if len(n.Cells) == 0 {
		return nil, nmr
	}
	return n, nmr
}
