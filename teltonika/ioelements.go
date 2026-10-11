// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package teltonika

import (
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// IOElement is one entry of the FMB AVL IO element table: our short name
// for the ID, its unit, and how the raw value is read.
//
// The IDs, sizes, signs, multipliers and units are facts from Teltonika's
// public FMB AVL ID list (wiki.teltonika-gps.com, "FMB AVL ID", firmware
// 03.18.18 and newer); the names are ours.
type IOElement struct {
	ID   uint16
	Name string
	// Unit of the value after Scale ("" when it has none).
	Unit string
	// Scale multiplies the raw value; 0 uses the raw value as is.
	Scale float64
	// Signed values are two's complement in the element's size.
	Signed bool
	kind   ioKind
}

type ioKind byte

const (
	ioNumber ioKind = iota
	ioBool          // 0/1 logic
	ioID            // an 8-byte identifier, shown as 16 hex digits
	ioText          // ASCII (Codec 8 Extended variable length)
	ioHex           // binary (Codec 8 Extended variable length)
)

// IOName returns our name and unit for an FMB AVL IO ID.
func IOName(id uint16) (name, unit string, ok bool) {
	e, ok := ioTable[id]
	return e.Name, e.Unit, ok
}

// IOElements lists the IO element table, sorted by ID.
func IOElements() []IOElement {
	out := make([]IOElement, 0, len(ioTable))
	for _, e := range ioTable {
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// value reads a fixed-size element (size 1, 2, 4 or 8 bytes).
func (e IOElement) value(v uint64, size int) any {
	switch e.kind {
	case ioBool:
		return v != 0
	case ioID:
		return fmt.Sprintf("%016X", v)
	}
	var f float64
	if e.Signed {
		shift := 64 - 8*size
		s := int64(v<<shift) >> shift
		if e.Scale == 0 {
			return s
		}
		f = float64(s)
	} else {
		if e.Scale == 0 {
			return v
		}
		f = float64(v)
	}
	if e.Scale < 1 {
		// Divide by the whole divisor so 12600 × 0.001 is exactly 12.6.
		return f / math.Round(1/e.Scale)
	}
	return f * e.Scale
}

// bytesValue reads a Codec 8 Extended variable-length element.
func (e IOElement) bytesValue(b []byte) any {
	if e.kind == ioText && utf8.Valid(b) {
		return strings.TrimRight(string(b), "\x00")
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

var ioTable = buildIOTable()

func buildIOTable() map[uint16]IOElement {
	t := map[uint16]IOElement{}
	add := func(id uint16, name, unit string, scale float64, signed bool, k ioKind) {
		if _, dup := t[id]; dup {
			panic("teltonika: IO ID " + strconv.Itoa(int(id)) + " listed twice")
		}
		t[id] = IOElement{ID: id, Name: name, Unit: unit, Scale: scale, Signed: signed, kind: k}
	}
	num := func(id uint16, name, unit string) { add(id, name, unit, 0, false, ioNumber) }
	scaled := func(id uint16, name, unit string, scale float64) { add(id, name, unit, scale, false, ioNumber) }
	signed := func(id uint16, name, unit string, scale float64) { add(id, name, unit, scale, true, ioNumber) }
	flag := func(id uint16, name string) { add(id, name, "", 0, false, ioBool) }
	ident := func(id uint16, name string) { add(id, name, "", 0, false, ioID) }

	// Permanent elements.
	flag(239, "ignition")
	flag(240, "movement")
	num(80, "dataMode", "") // 0..5: home, roaming, unknown network × stop, moving
	num(21, "gsm", "")      // signal 0..5
	num(200, "sleepMode", "")
	num(69, "gnssStatus", "")
	scaled(181, "pdop", "", 0.1)
	scaled(182, "hdop", "", 0.1)
	scaled(66, "externalVoltage", "V", 0.001)
	num(24, "gnssSpeed", "km/h")
	num(205, "gsmCellId", "")
	num(206, "gsmAreaCode", "")
	scaled(67, "batteryVoltage", "V", 0.001)
	scaled(68, "batteryCurrent", "A", 0.001)
	num(241, "gsmOperator", "")
	num(199, "tripOdometer", "m")
	num(16, "odometer", "m")
	flag(1, "din1")
	flag(2, "din2")
	flag(3, "din3")
	scaled(9, "ain1", "V", 0.001)
	scaled(6, "ain2", "V", 0.001)
	flag(179, "dout1")
	flag(180, "dout2")
	flag(380, "dout3")
	flag(381, "groundSense")
	scaled(12, "fuelUsedGps", "l", 0.001)
	scaled(13, "fuelRateGps", "l/100km", 0.01)
	signed(17, "axisX", "mG", 0)
	signed(18, "axisY", "mG", 0)
	signed(19, "axisZ", "mG", 0)
	num(11, "iccid1", "")
	num(14, "iccid2", "")
	flag(10, "sdCard")
	for i, id := range []uint16{72, 73, 74, 75} {
		signed(id, "dallasTemp"+strconv.Itoa(i+1), "°C", 0.1)
	}
	for i, id := range []uint16{76, 77, 79, 71} {
		ident(id, "dallasId"+strconv.Itoa(i+1))
	}
	ident(78, "iButton")
	ident(207, "rfid")
	ident(8, "authorizedIButton")
	for i, p := range [][2]uint16{{201, 202}, {203, 204}, {210, 211}, {212, 213}, {214, 215}} {
		n := strconv.Itoa(i + 1)
		signed(p[0], "llsFuel"+n, "", 0) // level in the sensor's own units or litres
		signed(p[1], "llsTemp"+n, "°C", 0)
	}
	scaled(15, "ecoScore", "", 0.01)
	num(113, "batteryLevel", "%")
	ident(238, "userId")
	num(237, "networkType", "")
	num(4, "pulseCount1", "")
	num(5, "pulseCount2", "")
	num(263, "btStatus", "")
	add(264, "barcodeId", "", 0, false, ioText)
	for i := 0; i < 4; i++ {
		n, base := strconv.Itoa(i+1), uint16(269+3*i)
		signed(base, "fuelSensor"+n+"Temp", "°C", 0)
		num(base+1, "fuelSensor"+n+"Level", "")
		scaled(base+2, "fuelSensor"+n+"Battery", "V", 0.01)
	}
	flag(303, "instantMovement")
	signed(327, "ul202FuelLevel", "mm", 0.1)
	num(483, "ul202Status", "")
	add(387, "iso6709", "", 0, false, ioText)
	add(403, "driverName", "", 0, false, ioText)
	num(404, "driverLicenseType", "")
	num(405, "driverGender", "")
	num(406, "driverCardId", "")
	num(407, "driverCardIssueYear", "")
	num(409, "driverStatusEvent", "")

	// Eventual elements.
	zones := []uint16{155, 156, 157, 158, 159, 61, 62, 63, 64, 65, 70, 88, 91, 92, 93, 94, 95, 96, 97, 98, 99, 153, 154,
		190, 191, 192, 193, 194, 195, 196, 197, 198, 208, 209, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226,
		227, 228, 229, 230, 231}
	for i, id := range zones {
		num(id, "geofenceZone"+strconv.Itoa(i+1), "") // 0 left, 1 entered, 2/3 over-speed end/start
	}
	num(175, "autoGeofence", "")
	num(250, "trip", "")
	num(255, "overSpeeding", "km/h")
	add(257, "crashTrace", "", 0, false, ioHex)
	num(285, "bloodAlcohol", "")
	flag(251, "idling")
	num(253, "greenDrivingType", "") // 1 acceleration, 2 braking, 3 cornering
	flag(246, "towing")
	flag(252, "unplug")
	num(247, "crashDetection", "")
	num(248, "immobilizer", "")
	num(254, "greenDrivingValue", "") // g×100 or rad×100 by type
	flag(249, "jamming")
	num(243, "greenDrivingDuration", "ms")
	flag(236, "alarm")
	num(258, "ecoMaximum", "")
	num(259, "ecoAverage", "")
	num(260, "ecoDuration", "ms")
	num(283, "drivingState", "")
	num(284, "drivingRecords", "")
	num(391, "privateMode", "")
	num(317, "crashCounter", "")
	add(330, "tripTrace", "", 0, false, ioHex)
	flag(244, "din2SpecialEvent")

	// OBD (Bluetooth OBD dongle) elements.
	add(256, "vin", "", 0, false, ioText)
	num(30, "obdDtcCount", "")
	num(31, "obdEngineLoad", "%")
	signed(32, "obdCoolantTemp", "°C", 0)
	signed(33, "obdShortFuelTrim", "%", 0)
	num(34, "obdFuelPressure", "kPa")
	num(35, "obdIntakeMap", "kPa")
	num(36, "obdRpm", "rpm")
	num(37, "obdSpeed", "km/h")
	signed(38, "obdTimingAdvance", "°", 0)
	signed(39, "obdIntakeAirTemp", "°C", 0)
	scaled(40, "obdMaf", "g/s", 0.01)
	num(41, "obdThrottle", "%")
	num(42, "obdRuntime", "s")
	num(43, "obdMilDistance", "km")
	scaled(44, "obdRelFuelRailPressure", "kPa", 0.1)
	scaled(45, "obdDirectFuelRailPressure", "kPa", 10)
	num(46, "obdCommandedEgr", "%")
	signed(47, "obdEgrError", "%", 0)
	num(48, "obdFuelLevel", "%")
	num(49, "obdDistanceSinceClear", "km")
	num(50, "obdBarometricPressure", "kPa")
	scaled(51, "obdModuleVoltage", "V", 0.001)
	num(52, "obdAbsoluteLoad", "%")
	signed(53, "obdAmbientTemp", "°C", 0)
	num(54, "obdMilTime", "min")
	num(55, "obdTimeSinceClear", "min")
	scaled(56, "obdAbsFuelRailPressure", "kPa", 0.1)
	num(57, "obdHybridBatteryLife", "%")
	num(58, "obdOilTemp", "°C")
	signed(59, "obdInjectionTiming", "°", 0.01)
	add(281, "obdFaultCodes", "", 0, false, ioText)
	scaled(60, "obdFuelRate", "l/100km", 0.01)
	num(389, "obdOemOdometer", "km")
	scaled(390, "obdOemFuelLevel", "l", 0.1)

	// CAN adapter (LV-CAN, ALL-CAN) elements.
	num(81, "canSpeed", "km/h")
	num(82, "canAcceleratorPedal", "%")
	scaled(83, "canFuelUsed", "l", 0.1)
	scaled(84, "canFuelLevelLitres", "l", 0.1)
	num(85, "canRpm", "rpm")
	num(87, "canOdometer", "m")
	num(89, "canFuelLevel", "%")
	num(90, "canDoorStatus", "")
	num(100, "canProgramNumber", "")
	ident(101, "canModuleId")
	num(102, "canEngineWorktime", "min")
	num(103, "canEngineWorktimeCounted", "min")
	num(105, "canOdometerCounted", "m")
	num(107, "canFuelUsedCounted", "ml")
	scaled(110, "canFuelRate", "l/h", 0.1)
	num(111, "canAdBlueLevel", "%")
	scaled(112, "canAdBlueLitres", "l", 0.1)
	num(114, "canEngineLoad", "%")
	signed(115, "canEngineTemp", "°C", 0.1)
	for i := uint16(0); i < 5; i++ {
		num(118+i, "canAxle"+strconv.Itoa(int(i)+1)+"Load", "kg")
	}
	num(123, "canControlFlags", "")
	num(124, "canAgriculturalFlags", "")
	num(125, "canHarvestingTime", "min")
	num(126, "canHarvestArea", "m2")
	num(129, "canGrainMoisture", "%")
	num(132, "canSecurityFlags", "")
	num(133, "tachoOdometer", "m")
	num(134, "canTripDistance", "m")
	num(135, "tachoSpeed", "km/h")
	num(136, "tachoCardPresence", "")
	num(137, "driver1States", "")
	num(138, "driver2States", "")
	num(139, "driver1ContinuousDriving", "min")
	num(140, "driver2ContinuousDriving", "min")
	num(141, "driver1BreakTime", "min")
	num(142, "driver2BreakTime", "min")
	num(143, "driver1ActivityDuration", "min")
	num(144, "driver2ActivityDuration", "min")
	num(145, "driver1DrivingTime", "min")
	num(146, "driver2DrivingTime", "min")
	ident(147, "driver1IdHigh")
	ident(148, "driver1IdLow")
	ident(149, "driver2IdHigh")
	ident(150, "driver2IdLow")
	signed(151, "canBatteryTemp", "°C", 0.1)
	num(152, "canBatteryLevel", "%")
	num(160, "canDtcCount", "")
	flag(232, "cngStatus")
	num(233, "cngUsed", "kg")
	num(234, "cngLevel", "%")
	num(235, "canOilLevel", "")
	num(304, "canBatteryRange", "m")
	add(282, "canDtcCodes", "", 0, false, ioText)

	// Bluetooth sensors.
	for i, id := range []uint16{25, 26, 27, 28} {
		signed(id, "bleTemp"+strconv.Itoa(i+1), "°C", 0.01)
	}
	for i, id := range []uint16{29, 20, 22, 23} {
		num(id, "bleBattery"+strconv.Itoa(i+1), "%")
	}
	for i, id := range []uint16{86, 104, 106, 108} {
		scaled(id, "bleHumidity"+strconv.Itoa(i+1), "%RH", 0.1)
	}
	for i := uint16(0); i < 4; i++ {
		num(306+i, "bleFuelFrequency"+strconv.Itoa(int(i)+1), "")
		num(335+i, "bleLuminosity"+strconv.Itoa(int(i)+1), "lx")
	}
	add(385, "beacons", "", 0, false, ioHex)
	return t
}
