// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package queclink

// The @Track HEX (binary) report format: a device whose <Protocol Format>
// (AT+GTSRI, AT+GTQSS) is 1 sends its reports in binary, while commands
// and the server's +SACK answers stay ASCII. Section 4 of the GV300N
// @Track Air Interface Protocol V3.01 describes it; the layout notes below
// are our own summary of that section.
//
// A frame starts with a 4-byte ASCII header and ends with 0x0D 0x0A,
// big-endian throughout:
//
//	+ACK <type 1> <mask 1> [len 1] …                 a command's acknowledgement (type: the command, table below)
//	+RSP/+BSP <type 1> <mask 4> [ERI mask 4] [len 2] … location report (+BSP: from the buffer)
//	+EVT/+BVT <type 1> <mask 4> [len 2] …            event report (+BVT: from the buffer)
//	+INF/+BNF <type 1> <mask 2> [expand 2] [len 2] … information report
//	+HBD <mask 1> [len 1] …                          heartbeat
//
// The mask (AT+GTHRM) says which items the frame carries; the length,
// when present, is the whole frame's. The two bytes before the tail are a
// CRC-16 (polynomial 0x1021, initial value 0xFFFF) from the type byte to
// the count number. The unique ID is 8 bytes: the IMEI two digits per
// byte (the last byte the fifteenth digit), or, by a mask bit, the
// device name. Coordinates are signed micro-degrees, times are a 2-byte
// year then month, day, hour, minute and second, the MCC and MNC are
// written as hex digits (0x0404 is MCC 404), LAC and cell ID are binary.
//
// The document's tables and its examples differ in places (the analogue
// input mode and RFID items, lengths that count the tail or not), and
// other families (GL300) number some messages differently. The decoder
// therefore reads the items the mask names, checks the result against the
// frame's length, and tries the known variations before it gives up.
//
// Also read, from facts in Traccar's Gl200 decoders (no public document):
// the newer binary frame that starts 0x2B 0x00 (a record list of tagged
// values, of which the GNSS item 0x52 is decoded). +CRD/+BRD crash data,
// +LGN, +DAT and +CAN frames are passed over by their length.

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/cB-Sigma/trackers/track"
)

// hexHeaders are the HEX frame headers (without '+') this package frames.
var hexHeaders = map[string]bool{
	"ACK": true, "RSP": true, "BSP": true, "EVT": true, "BVT": true, "INF": true, "BNF": true,
	"HBD": true, "CRD": true, "BRD": true, "LGN": true, "DAT": true, "CAN": true,
}

// hexRSP names the +RSP message types (GV300N table).
var hexRSP = map[int]string{
	0: "GTPNL", 1: "GTTOW", 3: "GTLBC", 4: "GTEPS", 5: "GTDIS", 6: "GTIOB", 7: "GTFRI", 8: "GTGEO", 9: "GTSPD",
	10: "GTSOS", 11: "GTRTL", 12: "GTDOG", 14: "GTAIS", 15: "GTHBM", 16: "GTIGL", 17: "GTIDA", 18: "GTERI",
	20: "GTGIN", 21: "GTGOT",
}

// hexEVT names the +EVT message types (GV300N table). Types from 22 on
// are numbered differently in other families, so they are named only for
// the GV300N's device type.
var hexEVT = map[int]string{
	1: "GTPNA", 2: "GTPFA", 3: "GTMPN", 4: "GTMPF", 6: "GTBPL", 7: "GTBTC", 8: "GTSTC", 9: "GTSTT", 10: "GTANT",
	11: "GTMON", 12: "GTPDP", 13: "GTIGN", 14: "GTIGF", 15: "GTUPD", 16: "GTIDN", 17: "GTIDF", 18: "GTDAT",
	20: "GTJDR", 21: "GTGSS", 22: "GTFLA", 23: "GTSTR", 24: "GTSTP", 25: "GTCRA", 27: "GTDOS", 28: "GTGES",
	29: "GTLSP", 30: "GTTMP", 31: "GTDTT", 32: "GTJDS", 33: "GTRMD", 34: "GTPHL", 37: "GTUFS",
}

// hexINF names the +INF message types.
var hexINF = map[int]string{
	1: "GTINF", 2: "GTGPS", 4: "GTCID", 5: "GTCSQ", 6: "GTVER", 7: "GTBAT", 8: "GTIOS", 9: "GTTMZ", 10: "GTGIR", 11: "GTGSV",
}

// hexACK names the command a +ACK acknowledges (its message type).
var hexACK = map[int]string{
	0: "GTBSI", 1: "GTSRI", 2: "GTQSS", 4: "GTCFG", 5: "GTTOW", 6: "GTEPS", 7: "GTDIS", 8: "GTOUT", 9: "GTIOB",
	10: "GTTMA", 11: "GTFRI", 12: "GTGEO", 13: "GTSPD", 14: "GTSOS", 15: "GTMON", 16: "GTRTO", 21: "GTUPD",
	22: "GTPIN", 23: "GTDAT", 24: "GTOWH", 25: "GTDOG", 26: "GTAIS", 27: "GTJDC", 28: "GTIDL", 29: "GTHBM",
	30: "GTHMC", 32: "GTURT", 34: "GTWLT", 35: "GTHRM", 36: "GTFFC", 37: "GTJBS", 38: "GTSSR", 41: "GTEFS",
	43: "GTIDA", 44: "GTACD", 45: "GTPDS", 46: "GTCRA", 47: "GTBZA", 48: "GTSPA", 49: "GTMUT", 50: "GTUDT",
	51: "GTTMP", 52: "GTFSC", 54: "GTPEO", 55: "GTCMS", 56: "GTTAP", 57: "GTCAN",
}

// rtoSub names AT+GTRTO's sub-commands by their number, as the ASCII
// acknowledgement writes them.
var rtoSub = []string{"GPS", "RTL", "READ", "REBOOT", "RESET", "PWROFF", "CID", "CSQ", "VER", "BAT", "IOS", "TMZ", "GIR"}

// gv300nType is the GV300N's device type byte.
const gv300nType = 0x25

// eventExtra is the length of the items an +EVT type carries between the
// satellites byte and the number of positions (GV300N tables); -1: it
// varies (found by the frame's length).
var eventExtra = map[string]int{
	"GTBPL": 2, "GTJDS": 1, "GTIGN": 4, "GTIGF": 4, "GTUPD": 3, "GTIDF": 4, "GTGSS": 5, "GTDOS": 2,
	"GTGES": 12, "GTTMP": 13, "GTRMD": 1, "GTMON": -1, "GTDAT": -1, "GTDTT": -1, "GTPHL": -1, "GTFLA": -1,
}

// Crc16 is the HEX frames' checksum (CRC-16, polynomial 0x1021, initial
// value 0xFFFF, no reflection) of b.
func Crc16(b []byte) uint16 {
	c := uint16(0xFFFF)
	for _, x := range b {
		c ^= uint16(x) << 8
		for i := 0; i < 8; i++ {
			if c&0x8000 != 0 {
				c = c<<1 ^ 0x1021
			} else {
				c <<= 1
			}
		}
	}
	return c
}

const maxHex = 4096

// unreadable is the skip of a HEX frame that does not decode.
func unreadable(detail string) error {
	return &track.Skip{Warning: track.Warning{Code: "messageUnreadable", Detail: detail,
		Msg: "A Queclink HEX report could not be read and was passed over."}}
}

// readHex reads the rest of a HEX frame whose '+' was consumed and
// returns the whole frame.
func readHex(r *bufio.Reader) ([]byte, error) {
	p, _ := r.Peek(3)
	if len(p) < 3 {
		return nil, io.ErrUnexpectedEOF
	}
	if p[0] == 0 { // 0x2B 0x00 <length 2>
		return readCounted(r, int(binary.BigEndian.Uint16(p[1:3])), false)
	}
	head := string(p)
	at, size := -1, 0 // offset of the length (counted from '+') and its size
	switch head {
	case "ACK":
		if q, _ := r.Peek(6); len(q) == 6 && q[4]&1 == 1 {
			at, size = 6, 1
		}
	case "HBD":
		if q, _ := r.Peek(5); len(q) == 5 && q[3]&1 == 1 {
			at, size = 5, 1
		}
	case "RSP", "BSP", "EVT", "BVT":
		if q, _ := r.Peek(8); len(q) == 8 && q[7]&0x80 != 0 {
			at, size = 9, 2
			if q[3] == 18 && (head == "RSP" || head == "BSP") { // GTERI: its ERI mask comes first
				at = 13
			}
		}
	case "INF", "BNF":
		if q, _ := r.Peek(6); len(q) == 6 && q[5]&1 == 1 {
			at, size = 7, 2
			if q[5]&0x80 != 0 {
				at = 9
			}
		}
	case "CRD", "BRD", "LGN":
		at, size = 6, 2
	}
	if at < 0 {
		return scanHex(r)
	}
	q, _ := r.Peek(at - 1 + size)
	if len(q) < at-1+size {
		return nil, io.ErrUnexpectedEOF
	}
	n := int(q[at-1])
	if size == 2 {
		n = int(binary.BigEndian.Uint16(q[at-1:]))
	}
	return readCounted(r, n, true)
}

// readCounted reads a frame of n bytes counted from its '+'. A frame that
// does not end where its length says (the document's examples count
// the length without the tail) takes the tail that follows, when it is
// there.
func readCounted(r *bufio.Reader, n int, crlf bool) ([]byte, error) {
	if n < 8 || n > maxHex {
		return nil, unreadable(fmt.Sprintf("length %d", n))
	}
	b := make([]byte, n)
	b[0] = '+'
	if _, err := io.ReadFull(r, b[1:]); err != nil {
		if errors.Is(err, io.EOF) {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	if crlf && !(b[n-2] == 0x0D && b[n-1] == 0x0A) && r.Buffered() >= 2 {
		if q, _ := r.Peek(2); q[0] == 0x0D && q[1] == 0x0A {
			_, _ = r.Discard(2)
			b = append(b, 0x0D, 0x0A)
		}
	}
	return b, nil
}

// scanHex reads a frame without a length: up to the 0x0D 0x0A after which
// the checksum holds, or the first one when no checksum holds and nothing
// further has arrived.
func scanHex(r *bufio.Reader) ([]byte, error) {
	first := -1
	for i := 1; i < maxHex && i < r.Size(); i++ {
		p, err := r.Peek(i + 1)
		if len(p) < i+1 {
			if first >= 0 {
				break
			}
			if err == nil || errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return nil, err
		}
		if p[i-1] != 0x0D || p[i] != 0x0A {
			continue
		}
		if first < 0 {
			first = i
		}
		f := append([]byte{'+'}, p[:i+1]...)
		if len(f) >= 10 && Crc16(f[4:len(f)-4]) == binary.BigEndian.Uint16(f[len(f)-4:]) {
			_, _ = r.Discard(i + 1)
			return f, nil
		}
		if r.Buffered() <= i+1 {
			break
		}
	}
	if first < 0 {
		return nil, unreadable("no frame end within 4 KiB")
	}
	p, _ := r.Peek(first + 1)
	f := append([]byte{'+'}, p...)
	_, _ = r.Discard(first + 1)
	return f, nil
}

// hexIMEI reads an 8-byte IMEI; ok is false when the bytes are not one.
func hexIMEI(b []byte) (string, bool) {
	var s strings.Builder
	for _, x := range b[:7] {
		if x > 99 {
			return "", false
		}
		fmt.Fprintf(&s, "%02d", x)
	}
	if b[7] > 9 {
		return "", false
	}
	fmt.Fprintf(&s, "%d", b[7])
	return s.String(), true
}

// hexName reads an 8-byte device name (zero padded).
func hexName(b []byte) (string, bool) {
	s := strings.TrimRight(string(b), "\x00")
	if s == "" {
		return "", false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7E {
			return "", false
		}
	}
	return s, true
}

// uid reads a unique ID: the IMEI, or the device name when byName.
func uid(b []byte, byName bool) (imei, name string, ok bool) {
	if !byName {
		imei, ok = hexIMEI(b)
		return imei, "", ok
	}
	name, ok = hexName(b)
	return "", name, ok
}

// hexTime reads a 7-byte time (UTC); zero when absent or not a date.
func hexTime(b []byte) time.Time {
	y := int(binary.BigEndian.Uint16(b))
	mo, d, h, mi, s := int(b[2]), int(b[3]), int(b[4]), int(b[5]), int(b[6])
	if y < 2000 || y > 2099 || mo < 1 || mo > 12 || d < 1 || d > 31 || h > 23 || mi > 59 || s > 59 {
		return time.Time{}
	}
	return time.Date(y, time.Month(mo), d, h, mi, s, 0, time.UTC)
}

// plausibleTime is a GPS time that is all zero or a date.
func plausibleTime(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return !hexTime(b).IsZero()
		}
	}
	return true
}

// hexDigits reads a 2-byte MCC or MNC written as hex digits (0x0404 is
// 404); a value with digits above 9 is read as binary.
func hexDigits(v uint16) int {
	s := fmt.Sprintf("%04X", v)
	if n, err := strconv.Atoi(s); err == nil {
		return n
	}
	return int(v)
}

// decimal reads an integer part of n bytes and a one-digit fraction byte
// (speed, mileage); a fraction above 9 means the whole was one number of
// tenths, as some firmware writes it.
func decimal(b []byte) float64 {
	var whole uint64
	for _, x := range b[:len(b)-1] {
		whole = whole<<8 | uint64(x)
	}
	frac := b[len(b)-1]
	if frac > 9 {
		return float64(whole<<8|uint64(frac)) / 10
	}
	return float64(whole) + float64(frac)/10
}

// layout is the item sizes of a +RSP/+EVT frame, by its mask and a
// variation.
type layout struct {
	mask              uint32
	mode, rfid, can   bool // analogue input mode, RFID, CAN data present
	forceMileage      bool // GTIGN/GTIGF: total mileage regardless of the mask
	block             int  // one position block's size
	head, io, tailLen int
}

func (l *layout) bit(n int) bool { return l.mask>>n&1 == 1 }

func newLayout(mask uint32, mode, rfid, can, forceMileage bool) layout {
	l := layout{mask: mask, mode: mode, rfid: rfid, can: can, forceMileage: forceMileage}
	l.block = 1 + 4 + 4 + 7
	for i, n := range []int{3, 2, 2, 9} { // speed, azimuth, altitude, cell
		if l.bit(i) {
			l.block += n
		}
	}
	for _, it := range []struct {
		on bool
		n  int
	}{{l.bit(11), 1}, {l.bit(12), 2}, {mode, 2}, {l.bit(14), 2}, {l.bit(15), 2}, {l.bit(17), 2}, {l.bit(18), 1}, {l.bit(19), 1}} {
		if it.on {
			l.io += it.n
		}
	}
	for _, it := range []struct {
		on bool
		n  int
	}{{l.bit(20), 3}, {l.bit(21) || forceMileage, 5}, {l.bit(22), 3}, {l.bit(23), 6}, {rfid, 4}, {can, 90}} {
		if it.on {
			l.tailLen += it.n
		}
	}
	return l
}

// plausibleBlock checks one position block.
func (l *layout) plausibleBlock(b []byte) bool {
	if len(b) < l.block || b[0] > 50 {
		return false
	}
	i := 1
	if l.bit(0) {
		i += 3
	}
	if l.bit(1) {
		if binary.BigEndian.Uint16(b[i:]) > 360 {
			return false
		}
		i += 2
	}
	if l.bit(2) {
		i += 2
	}
	lon := int32(binary.BigEndian.Uint32(b[i:]))
	lat := int32(binary.BigEndian.Uint32(b[i+4:]))
	if lon > 180e6 || lon < -180e6 || lat > 90e6 || lat < -90e6 {
		return false
	}
	return plausibleTime(b[i+8 : i+15])
}

// readBlock decodes one position block.
func (l *layout) readBlock(b []byte, sats *int) (*track.Fix, *track.Network) {
	acc := int(b[0])
	i := 1
	x := &track.Fix{}
	if l.bit(0) {
		x.Speed = track.F(decimal(b[i : i+3]))
		i += 3
	}
	if l.bit(1) {
		x.Heading = track.F(float64(binary.BigEndian.Uint16(b[i:])))
		i += 2
	}
	if l.bit(2) {
		x.Alt = track.F(float64(int16(binary.BigEndian.Uint16(b[i:]))))
		i += 2
	}
	x.Lon = float64(int32(binary.BigEndian.Uint32(b[i:]))) / 1e6
	x.Lat = float64(int32(binary.BigEndian.Uint32(b[i+4:]))) / 1e6
	x.Time = hexTime(b[i+8 : i+15])
	i += 15
	x.Valid = acc > 0 && (x.Lat != 0 || x.Lon != 0)
	if acc > 0 {
		x.HDOP = track.F(float64(acc))
	}
	if sats != nil {
		v := *sats
		x.Sats = &v
	}
	var n *track.Network
	if l.bit(3) {
		mcc := hexDigits(binary.BigEndian.Uint16(b[i:]))
		mnc := hexDigits(binary.BigEndian.Uint16(b[i+2:]))
		lac := int(binary.BigEndian.Uint16(b[i+4:]))
		cid := int64(binary.BigEndian.Uint16(b[i+6:]))
		if lac != 0 || cid != 0 {
			n = &track.Network{Cells: []track.Cell{{MCC: mcc, MNC: mnc, LAC: lac, CID: cid}}}
		}
	}
	return x, n
}

// hexFrame is what every HEX frame has in common.
type hexFrame struct {
	head    string // RSP, EVT, … with B for buffered
	typ     int
	mask    uint32
	devType int // -1 absent
	version string
	imei    string
	name    string
	sent    time.Time
	count   string // "" absent
	end     int    // index of the checksum
}

// parseHex decodes a whole HEX frame.
func (c *codec) parseHex(b []byte) (*track.Message, error) {
	if len(b) >= 4 && b[1] == 0 {
		return c.parseRecords(b)
	}
	head := string(b[1:4])
	if len(b) < 12 {
		return nil, unreadable("+" + head + " too short")
	}
	var warn []track.Warning
	if b[len(b)-2] == 0x0D && b[len(b)-1] == 0x0A {
		if Crc16(b[4:len(b)-4]) != binary.BigEndian.Uint16(b[len(b)-4:]) {
			warn = append(warn, track.Warning{Code: "crcMismatch", Detail: "+" + head,
				Msg: "A Queclink HEX report's checksum does not match its content; it was read anyway."})
		}
	} else {
		return nil, unreadable("+" + head + " without its 0x0D 0x0A end")
	}
	var m *track.Message
	var err error
	switch head {
	case "ACK":
		m, err = c.hexAck(b)
	case "HBD":
		m, err = c.hexHeartbeat(b)
	case "RSP", "BSP", "EVT", "BVT":
		m, err = c.hexReport(b)
	case "INF", "BNF":
		m, err = c.hexInfo(b)
	default:
		return nil, &track.Skip{Warning: track.Warning{Code: "unknownMessage", Detail: "+" + head,
			Msg: "A Queclink HEX message this codec does not read (crash data, data transfer or CAN) was passed over."}}
	}
	if err != nil {
		return nil, err
	}
	m.Warnings = append(m.Warnings, warn...)
	return m, nil
}

// identify fills the frame's IMEI from its unique ID, or from the
// connection when the frame names the device by name.
func (c *codec) identify(m *track.Message, f *hexFrame) error {
	switch {
	case f.imei != "":
		m.IMEI = f.imei
	case c.imei != "":
		m.IMEI = c.imei
	default:
		return &track.Skip{Warning: track.Warning{Code: "messageUnreadable", Detail: "device name " + strconv.Quote(f.name),
			Msg: "A Queclink HEX report names the device by its device name instead of its IMEI, and no earlier report on this connection gave the IMEI. Clear the device-name bit in the AT+GTHRM masks."}}
	}
	if f.name != "" {
		m.Details = map[string]any{"deviceName": f.name}
	}
	return nil
}

// version is the protocol version as the ASCII format writes it: device
// type and protocol version in hex.
func versionOf(dev int, pv []byte) string {
	if dev < 0 || len(pv) != 2 {
		return ""
	}
	return fmt.Sprintf("%02X%02X%02X", dev, pv[0], pv[1])
}

// front reads device type, protocol version, firmware version and the
// unique ID at i by the mask bits devBit, pvBit and fwBit; when the ID
// does not read there, all three are taken as present (the document's
// examples carry them with their bits clear). It returns the index after
// the unique ID.
func front(b []byte, i int, mask uint32, devBit, pvBit, fwBit int, byName bool, f *hexFrame) (int, bool) {
	try := func(dev, pv, fw bool) (int, bool) {
		j := i
		f.devType, f.version = -1, ""
		var pvb []byte
		if dev {
			if j >= len(b) {
				return 0, false
			}
			f.devType = int(b[j])
			j++
		}
		if pv {
			if j+2 > len(b) {
				return 0, false
			}
			pvb = b[j : j+2]
			j += 2
		}
		if fw {
			j += 2
		}
		if j+8 > len(b) {
			return 0, false
		}
		imei, name, ok := uid(b[j:j+8], byName)
		if !ok {
			return 0, false
		}
		f.imei, f.name = imei, name
		f.version = versionOf(f.devType, pvb)
		return j + 8, true
	}
	if j, ok := try(mask>>devBit&1 == 1, mask>>pvBit&1 == 1, mask>>fwBit&1 == 1); ok {
		return j, true
	}
	return try(true, true, true)
}

// trailer reads the send time and count number before the checksum by
// the mask bits; it returns the index where they start.
func trailer(b []byte, mask uint32, timeBit, countBit int, f *hexFrame) int {
	end := len(b) - 4
	f.end = end
	if mask>>countBit&1 == 1 && end-2 >= 0 {
		f.count = fmt.Sprintf("%04X", binary.BigEndian.Uint16(b[end-2:]))
		end -= 2
	}
	if mask>>timeBit&1 == 1 && end-7 >= 0 {
		f.sent = hexTime(b[end-7 : end])
		end -= 7
	}
	return end
}

// hexAck reads +ACK <type> <mask> [len] [dev] [pv] [fw] <uid 8> <ID>
// <serial 2> [send time] [count].
func (c *codec) hexAck(b []byte) (*track.Message, error) {
	f := &hexFrame{head: "ACK", typ: int(b[4]), mask: uint32(b[5])}
	i := 6
	if f.mask&1 == 1 {
		i++
	}
	j, ok := front(b, i, f.mask, 1, 2, 3, f.mask>>4&1 == 1, f)
	end := trailer(b, f.mask, 5, 6, f)
	if !ok || end-2 < j+1 {
		return nil, unreadable("+ACK fields")
	}
	m := &track.Message{Kind: "response"}
	if err := c.identify(m, f); err != nil {
		return nil, err
	}
	serial := fmt.Sprintf("%04X", binary.BigEndian.Uint16(b[end-2:]))
	var id uint64
	for _, x := range b[j : end-2] {
		id = id<<8 | uint64(x)
	}
	name, known := hexACK[f.typ]
	if !known {
		name = fmt.Sprintf("type%d", f.typ)
	}
	if m.Details == nil {
		m.Details = map[string]any{}
	}
	m.Details["ack"], m.Details["serial"], m.Details["format"] = name, serial, "hex"
	sub := ""
	if name == "GTRTO" && id < uint64(len(rtoSub)) {
		sub = rtoSub[id]
		m.Details["subCommand"] = sub
	} else if id != 0 {
		m.Details["id"] = int(id)
	}
	// The answer as the ASCII format writes it.
	fields := []string{"+ACK:" + name, f.version, m.IMEI, f.name}
	if sub != "" {
		fields = append(fields, sub)
	}
	sent := ""
	if !f.sent.IsZero() {
		sent = f.sent.Format("20060102150405")
	}
	text := strings.Join(append(fields, serial, sent, f.count), ",") + "$"
	m.Response = &text
	if known {
		m.Correlation = name + "/" + serial
	}
	c.sack(m, f.count)
	return m, nil
}

// hexHeartbeat reads +HBD <mask> [len] [dev] [pv] [fw] [uid] [send time]
// [count]; it is answered +SACK:GTHBD,<version>,<count>$.
func (c *codec) hexHeartbeat(b []byte) (*track.Message, error) {
	f := &hexFrame{head: "HBD", mask: uint32(b[4]), devType: -1}
	i := 5
	if f.mask&1 == 1 {
		i++
	}
	end := trailer(b, f.mask, 5, 6, f)
	if f.mask>>7&1 == 1 {
		if end-8 < i {
			return nil, unreadable("+HBD fields")
		}
		imei, name, ok := uid(b[end-8:end], f.mask>>4&1 == 1)
		if !ok {
			return nil, unreadable("+HBD unique ID")
		}
		f.imei, f.name = imei, name
		end -= 8
	}
	mid := b[i:end]
	if len(mid) >= 3 && (f.mask>>1&1 == 1 || len(mid) == 5) {
		f.version = versionOf(int(mid[0]), mid[1:3])
	}
	m := &track.Message{Kind: "heartbeat"}
	if err := c.identify(m, f); err != nil {
		return nil, err
	}
	count := f.count
	if count == "" {
		count = "0000"
	}
	m.Reply = []byte("+SACK:GTHBD," + f.version + "," + count + "$")
	rec := track.Record{Time: f.sent}
	if f.version != "" {
		rec.Status = map[string]any{"protocolVersion": f.version}
	}
	m.Records = []track.Record{rec}
	return m, nil
}

// hexReport reads +RSP/+BSP and +EVT/+BVT.
func (c *codec) hexReport(b []byte) (*track.Message, error) {
	head := string(b[1:4])
	event := head == "EVT" || head == "BVT"
	history := head[0] == 'B'
	if len(b) < 30 {
		return nil, unreadable("+" + head + " too short")
	}
	f := &hexFrame{head: head, typ: int(b[4]), mask: binary.BigEndian.Uint32(b[5:9])}
	i := 9
	var name string
	if event {
		name = hexEVT[f.typ]
	} else {
		name = hexRSP[f.typ]
		if f.typ == 18 {
			i += 4 // the ERI mask
		}
	}
	if f.mask>>7&1 == 1 {
		i += 2
	}
	j, ok := front(b, i, f.mask, 8, 9, 10, f.mask>>6&1 == 1, f)
	if !ok {
		return nil, unreadable("+" + head + " unique ID")
	}
	if event && f.typ >= 22 && f.devType != gv300nType {
		name = ""
	}
	tailEnd := trailer(b, f.mask, 4, 5, f)
	m := &track.Message{Kind: "normal"}
	if history {
		m.Kind = "history"
	}
	if err := c.identify(m, f); err != nil {
		return nil, err
	}

	// Find the layout variation and the type's extra items that fit the
	// frame's length.
	type fit struct {
		l     layout
		extra int
		n     int
		tail  bool // the items after the positions were located
	}
	var variants []layout
	ign := name == "GTIGN" || name == "GTIGF"
	for _, mode := range []bool{f.mask>>13&1 == 1, f.mask>>13&1 == 0} {
		for _, rfid := range []bool{f.mask>>24&1 == 1, f.mask>>24&1 == 0} {
			for _, can := range []bool{false, f.mask>>25&1 == 1} {
				for _, fm := range []bool{false, ign} {
					variants = append(variants, newLayout(f.mask, mode, rfid, can, fm))
				}
			}
		}
	}
	known := -1
	if event {
		known = 0
		if v, ok := eventExtra[name]; ok {
			known = v
		}
	} else {
		known = 1
		switch name {
		case "GTSOS":
			known = 2
		case "GTLBC":
			if p := j + newLayout(f.mask, f.mask>>13&1 == 1, false, false, false).io + 1; p < len(b) {
				known = 1 + int(b[p]>>4)
			}
		case "GTIDA", "GTERI":
			known = -1
		}
	}
	try := func(l layout, e int, exact bool) (fit, bool) {
		p := j + l.io + e
		if e < 0 || p >= tailEnd {
			return fit{}, false
		}
		n := int(b[p])
		if n < 1 || n > 15 {
			return fit{}, false
		}
		need := p + 1 + n*l.block
		if exact && need+l.tailLen != tailEnd || !exact && need > tailEnd {
			return fit{}, false
		}
		for k := 0; k < n; k++ {
			if !l.plausibleBlock(b[p+1+k*l.block:]) {
				return fit{}, false
			}
		}
		return fit{l: l, extra: e, n: n, tail: exact}, true
	}
	var got fit
	found := false
	for _, l := range variants { // the type's own items
		if got, found = try(l, known, true); found {
			break
		}
	}
	for e := 0; !found && e <= 64; e++ { // any items
		for _, l := range variants {
			if got, found = try(l, e, true); found {
				break
			}
		}
	}
	if !found { // positions without the items after them
		for _, e := range append([]int{known}, seq(0, 64)...) {
			if got, found = try(variants[0], e, false); found {
				break
			}
		}
	}
	if !found {
		return nil, unreadable(fmt.Sprintf("+%s type %d: no position block fits the frame", head, f.typ))
	}

	// The items before the positions.
	l := got.l
	st := map[string]any{}
	p := j
	var sats *int
	if l.bit(11) {
		if v := int(b[p]); v <= 100 {
			st["batteryLevel"] = v
		}
		p++
	}
	if l.bit(12) {
		st["externalVoltage"] = float64(binary.BigEndian.Uint16(b[p:])) / 1000
		p += 2
	}
	if l.mode {
		p += 2
	}
	for a, bit := range []int{14, 15} {
		if l.bit(bit) {
			st[fmt.Sprintf("analog%d", a+1)] = float64(binary.BigEndian.Uint16(b[p:])) / 1000
			p += 2
		}
	}
	if l.bit(17) {
		in, out := b[p], b[p+1]
		st["ignition"] = in&1 == 1
		for k := 1; k <= 3; k++ {
			st[fmt.Sprintf("din%d", k)] = in>>k&1 == 1
		}
		for k := 0; k < 3; k++ {
			st[fmt.Sprintf("dout%d", k+1)] = out>>k&1 == 1
		}
		p += 2
	}
	if l.bit(18) {
		motion(fmt.Sprintf("%02X", b[p]), st)
		p++
	}
	if l.bit(19) {
		v := int(b[p] & 0x0F)
		sats = &v
		p++
	}
	extra := b[p : p+got.extra]
	p += got.extra + 1

	recs := make([]track.Record, 0, got.n)
	for k := 0; k < got.n; k++ {
		x, net := l.readBlock(b[p+k*l.block:], sats)
		recs = append(recs, track.Record{Fix: x, Network: net})
	}
	p += got.n * l.block

	// The items after the positions.
	if got.tail {
		if l.bit(20) {
			p += 3
		}
		if l.bit(21) || l.forceMileage {
			st["odometer"] = decimal(b[p : p+5])
			p += 5
		}
		if l.bit(22) {
			p += 3
		}
		if l.bit(23) {
			h := binary.BigEndian.Uint32(b[p:])
			st["hourMeter"] = fmt.Sprintf("%d:%02d:%02d", h, b[p+4], b[p+5])
			p += 6
		}
		if l.rfid {
			if v := binary.BigEndian.Uint32(b[p:]); v != 0 && v != 0xFFFFFFFF {
				st["rfid"] = fmt.Sprintf("%08X", v)
			}
		}
	}

	// What the type means.
	var alerts []track.Alert
	alert := func(typ string) { alerts = append(alerts, track.NewAlert(typ, name)) }
	rt := ""
	if !event && len(extra) > 0 {
		rt = fmt.Sprintf("%02X", extra[0])
	}
	switch name {
	case "GTBPL":
		if len(extra) == 2 {
			st["batteryVoltage"] = float64(binary.BigEndian.Uint16(extra)) / 1000
		}
	case "GTPNA":
		st["devicePower"] = true
	case "GTPFA":
		st["devicePower"] = false
	case "GTIDF":
		st["idling"] = false
	case "GTRMD":
		if len(extra) == 1 {
			st["roaming"] = int(extra[0])
		}
	case "GTGSS":
		if len(extra) >= 1 {
			st["gpsSignal"] = extra[0] == 1
		}
	}
	if name != "" {
		c.typed(name, rt, nil, -1, st, alert)
		if t, ok := c.cfg.alerts[name]; ok {
			alerts = []track.Alert{track.NewAlert(t, name)}
		}
	} else {
		m.Warnings = append(m.Warnings, track.Warning{Code: "unknownMessage", Detail: fmt.Sprintf("+%s type %d", head, f.typ),
			Msg: "A Queclink HEX report of a type this codec does not name; its positions were read."})
	}
	if m.Details == nil {
		m.Details = map[string]any{}
	}
	m.Details["format"] = "hex"
	if name != "" {
		m.Details["report"] = name
	}
	last := &recs[len(recs)-1]
	if len(st) > 0 {
		last.Status = st
	}
	last.Alerts = alerts
	for k := range recs {
		recs[k].History = history
		if recs[k].Fix != nil && !recs[k].Fix.Time.IsZero() {
			recs[k].Time = recs[k].Fix.Time
		} else {
			recs[k].Time = f.sent
		}
	}
	for _, a := range alerts {
		if a.Type == "emergency" && !history {
			m.Kind = "emergency"
		}
	}
	m.Records = recs
	c.sack(m, f.count)
	return m, nil
}

func seq(from, to int) []int {
	s := make([]int, 0, to-from+1)
	for i := from; i <= to; i++ {
		s = append(s, i)
	}
	return s
}

// hexInfo reads +INF/+BNF: <type> <mask 2> [expand 2] [len 2] <uid 8>
// [dev] [pv] [fw] and the groups the mask's high byte (and the expand
// mask) names, then [send time] [count].
func (c *codec) hexInfo(b []byte) (*track.Message, error) {
	f := &hexFrame{head: string(b[1:4]), typ: int(b[4]), mask: uint32(binary.BigEndian.Uint16(b[5:7])), devType: -1}
	i := 7
	expand := uint16(0)
	if f.mask&0x80 != 0 {
		expand = binary.BigEndian.Uint16(b[i:])
		i += 2
	}
	if f.mask&1 == 1 {
		i += 2
	}
	if i+8 > len(b) {
		return nil, unreadable("+INF too short")
	}
	imei, name, ok := uid(b[i:i+8], f.mask>>1&1 == 1)
	if !ok {
		return nil, unreadable("+INF unique ID")
	}
	f.imei, f.name = imei, name
	i += 8
	var pv []byte
	if f.mask>>2&1 == 1 {
		f.devType = int(b[i])
		i++
	}
	if f.mask>>3&1 == 1 {
		pv = b[i : i+2]
		i += 2
	}
	fw := ""
	if f.mask>>4&1 == 1 {
		fw = fmt.Sprintf("%04X", binary.BigEndian.Uint16(b[i:]))
		i += 2
	}
	f.version = versionOf(f.devType, pv)
	end := trailer(b, f.mask, 5, 6, f)
	m := &track.Message{Kind: "normal"}
	if f.head == "BNF" {
		m.Kind = "history"
	}
	if err := c.identify(m, f); err != nil {
		return nil, err
	}
	if m.Details == nil {
		m.Details = map[string]any{}
	}
	m.Details["format"] = "hex"
	if n, ok := hexINF[f.typ]; ok {
		m.Details["report"] = n
	}
	st := map[string]any{}
	var net *track.Network
	g := func(bit int) bool { return f.mask>>(8+bit)&1 == 1 }
	size := 4 // motion, reserved, satellites, mode
	if g(0) {
		size += 6
	}
	if g(1) {
		size += 16
	}
	for _, it := range []struct {
		bit, n int
	}{{2, 20}, {3, 6}, {4, 10}, {5, 2}, {6, 3}} {
		if g(it.bit) {
			size += it.n
		}
	}
	gir := i + size
	if g(7) && gir+2 <= end {
		size += 2 + 10*int(b[gir+1])
	}
	if expand&1 == 1 && i+size < end {
		size += 1 + 2*int(b[i+size])
	}
	if expand>>2&1 == 1 && i+size < end {
		size += 1 + int(b[i+size])
	}
	if i+size == end { // the groups fit the frame: read them
		p := i
		if g(0) {
			st["firmware"], st["hardware"] = fw, fmt.Sprintf("%04X", binary.BigEndian.Uint16(b[p:]))
			p += 6
		}
		if g(1) {
			st["analog1"] = float64(binary.BigEndian.Uint16(b[p+1:])) / 1000
			st["analog2"] = float64(binary.BigEndian.Uint16(b[p+3:])) / 1000
			in, out := b[p+12], b[p+13]
			st["ignition"] = in&1 == 1
			for k := 1; k <= 3; k++ {
				st[fmt.Sprintf("din%d", k)] = in>>k&1 == 1
			}
			for k := 0; k < 3; k++ {
				st[fmt.Sprintf("dout%d", k+1)] = out>>k&1 == 1
			}
			p += 16
		}
		motion(fmt.Sprintf("%02X", b[p]), st)
		p += 4
		if g(2) {
			p += 20
		}
		if g(3) {
			fl := b[p]
			st["mainPower"] = fl&0x80 != 0
			st["charging"] = fl&0x20 != 0
			st["externalVoltage"] = float64(binary.BigEndian.Uint16(b[p+1:])) / 1000
			st["batteryVoltage"] = float64(binary.BigEndian.Uint16(b[p+3:])) / 1000
			if v := int(b[p+5]); v <= 100 {
				st["batteryLevel"] = v
			}
			p += 6
		}
		if g(4) {
			st["iccid"] = strings.TrimRight(fmt.Sprintf("%X", b[p:p+10]), "F")
			p += 10
		}
		if g(5) {
			if v := int(b[p]); v != 99 {
				st["gsm"] = v
			}
			p += 2
		}
		if g(6) {
			p += 3
		}
		if g(7) {
			n := int(b[p+1])
			p += 2
			net = &track.Network{}
			for k := 0; k < n; k++ {
				q := b[p+10*k:]
				net.Cells = append(net.Cells, track.Cell{MCC: hexDigits(binary.BigEndian.Uint16(q)), MNC: hexDigits(binary.BigEndian.Uint16(q[2:])),
					LAC: int(binary.BigEndian.Uint16(q[4:])), CID: int64(binary.BigEndian.Uint16(q[6:]))})
			}
		}
	} else {
		m.Warnings = append(m.Warnings, track.Warning{Code: "fieldUnreadable", Detail: fmt.Sprintf("+INF type %d", f.typ),
			Msg: "A Queclink HEX information report's items do not match its masks; only the device was read."})
	}
	if fw != "" && st["firmware"] == nil && f.typ == 6 {
		st["firmware"] = fw
	}
	if len(st) > 0 || net != nil {
		m.Records = []track.Record{{Time: f.sent, Status: st, Network: net}}
	}
	c.sack(m, f.count)
	return m, nil
}

// varlen reads a 1- or 2-byte length (bit 7 of the first byte says 2).
func varlen(b []byte, i int) (int, int, bool) {
	if i >= len(b) {
		return 0, i, false
	}
	v := int(b[i])
	if v&0x80 == 0 {
		return v, i + 1, true
	}
	if i+1 >= len(b) {
		return 0, i, false
	}
	return (v&0x7F)<<8 | int(b[i+1]), i + 2, true
}

// parseRecords reads the 0x2B 0x00 frame: <length 2> <flags> [frame
// count and number 2] <IMEI 8, BCD with a leading nibble> <device type 2>
// <protocol version 2> <custom version 1> <reserved length 1 + bytes>,
// then records <length> <time 4> <count 2> <ID> <event> <items: ID,
// length, value>, then <count 2> <check> '$'.
func (c *codec) parseRecords(b []byte) (*track.Message, error) {
	n := len(b)
	if n < 24 || b[n-1] != '$' {
		return nil, unreadable("0x2B00 frame end")
	}
	i := 4
	if b[i]&0x80 != 0 {
		i += 2
	}
	i++
	imei := fmt.Sprintf("%X", b[i:i+8])[1:]
	if !digits(imei) {
		return nil, unreadable("0x2B00 IMEI")
	}
	i += 8 + 5
	i += 1 + int(b[i])
	m := &track.Message{IMEI: imei, Kind: "normal", Details: map[string]any{"format": "hex"}}
	end := n - 4
	for i < end {
		start := i
		l, j, ok := varlen(b, i)
		if !ok || l == 0 || start+l > end || j+8 > start+l {
			return nil, unreadable("0x2B00 record")
		}
		rec := track.Record{Time: time.Unix(int64(binary.BigEndian.Uint32(b[j:])), 0).UTC(),
			Status: map[string]any{"eventCode": int(b[j+7])}}
		j += 8
		for j < start+l {
			id, k, ok1 := varlen(b, j)
			size, k2, ok2 := varlen(b, k)
			if !ok1 || !ok2 || k2+size > start+l {
				return nil, unreadable("0x2B00 item")
			}
			v := b[k2 : k2+size]
			if id == 0x52 && size >= 22 {
				x := &track.Fix{
					Valid: v[0]>>2&3 == 2,
					Lon:   float64(int32(binary.BigEndian.Uint32(v[1:]))) / 1e6,
					Lat:   float64(int32(binary.BigEndian.Uint32(v[5:]))) / 1e6,
					Time:  time.Unix(int64(binary.BigEndian.Uint32(v[9:])), 0).UTC(),
				}
				x.Speed = track.F(float64(binary.BigEndian.Uint16(v[13:])) / 10)
				x.HDOP = track.F(float64(v[15]) / 10)
				x.Heading = track.F(float64(binary.BigEndian.Uint16(v[16:])))
				x.Alt = track.F(float64(int(v[18])<<16|int(v[19])<<8|int(v[20])) / 10)
				s := int(v[21])
				x.Sats = &s
				rec.Fix = x
				rec.Time = x.Time
			}
			j = k2 + size
		}
		m.Records = append(m.Records, rec)
		i = start + l
	}
	return m, nil
}
