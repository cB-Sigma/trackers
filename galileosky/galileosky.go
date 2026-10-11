// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

// Package galileosky is the Galileosky binary tag protocol of the
// Galileosky GPS/GLONASS terminals: packet reading and writing, decoding
// into track.Message, and command framing. Our own implementation from
// Galileosky's public description of its server exchange protocol (the
// "Server exchange protocol" chapter and its tag table in "User's Manual
// GalileoSky GPS/GLONASS v5.0", firmware 0200), with the lengths of tags
// added in later firmware from Traccar's decoder.
//
// A packet is a header byte, a 16-bit length (little endian; the high bit
// says the device's archive holds more), the tags (a tag number and its
// value, little endian) and a CRC-16/MODBUS of everything before it. The
// server confirms each packet with 0x02 and the packet's checksum (a
// packet not confirmed, or confirmed with another checksum, is sent
// again). Read from the device:
//
//   - 0x01 packets: the head packet (hardware and firmware version, IMEI,
//     device identifier) and main packets of one or more records; a
//     record starts again where a tag number is not above the one before
//     it (tags are in ascending order within a record). Records of a
//     packet with the archive flag set are marked as history.
//   - 0x01 packets with tags 0xE0 (command number) and 0xE1 (answer text):
//     a command's answer, with its number as Message.Correlation.
//   - 0x07 picture parts (part number and bytes), confirmed with 0x07 and
//     the checksum; an empty part ends the picture, which becomes status
//     image ([]byte). From Traccar's decoder; Galileosky's manual we
//     followed does not describe them.
//
// Tags read: 0x01 hardwareVersion, 0x02 firmwareVersion, 0x03 IMEI, 0x04
// deviceId, 0x10 recordNumber, 0x20 time, 0x30 coordinates (satellites,
// validity, latitude and longitude), 0x33 speed and direction, 0x34
// altitude, 0x35 HDOP, 0x40 device status (statusWord; moving, ignition,
// gsmSignal and the alerts below), 0x41 externalVoltage, 0x42
// batteryVoltage (V), 0x43 deviceTemp, 0x44 acceleration, 0x45 outputs,
// 0x46 inputs, 0x47 ecoDrive, 0x48 statusExtended, 0x50-0x57 in0..in7,
// 0x58-0x59 rs232_0/1, 0x60-0x6F fuel0..fuel15 (and fuelTemp3..15),
// 0x70-0x77 temp0..7 (and tempId), 0x80-0x87 DS1923 temperature and
// humidity, 0x88-0x8C fuel sensor temperatures, 0x90 and 0xD3 iButton
// keys (driverId, driverId2), 0xC0 fuelUsed, 0xC1 fuelLevel, coolantTemp
// and rpm, 0xC2 canMileage, 0xC3 canB1, the CAN registers 0xA0-0xAF,
// 0xB0-0xB9, 0xC4-0xD2, 0xD6-0xDF and 0xF0-0xF9 (can8BitR0.., can16BitR0..,
// can32BitR0..), 0xD4 odometer, 0xD5 iButtonState, 0xE2-0xE9 userData0..7,
// 0xEA userArray (hex) and 0xFE extended tags (kept as hex,
// extendedTags). Tags of a known length but no meaning here go under
// "tags" as hex. A tag of unknown length ends the reading of its packet:
// the records read so far are kept, the packet is confirmed (otherwise the
// device sends it forever) and the warning unknownTag names it; the
// profile's tagLengths gives it a length.
//
// Status bits become alerts when they turn on: 15 alarm (emergency), 10
// shock (impact), 1 incline (tilt), 6 GNSS aerial disconnected
// (gnss-antenna-cut), 5 internal battery low (low-battery).
//
// Not read: compressed packets (0x08; the device's "Protocol 4", not in
// the manual we followed) are passed over unconfirmed with the warning
// compressedPacket (set the device to "Protocol 0"); Garmin FMI packets
// (0x06) are passed over with the warning garminFmi; XTEA-encrypted data
// is not read (the device's "Key" must be 0).
//
// Commands are command packets (Frame): tags 0x03 IMEI, 0x04 device
// identifier, 0xE0 the command number (the sequence number) and 0xE1 the
// command text (at most 255 characters); the device answers with the
// same number, so the codec is a strict track.Correlator. Named commands
// (track.Named), from the manual's command list: engineStop "Out 0,0"
// and engineResume "Out 0,1" (output 0; other wiring takes a profile
// template), locate "Status" (its answer holds the position), reboot
// "Reset". The manual's WrPeriod sets the moving and parked periods
// together, so interval has no default: set namedCommands.interval (for
// example "WrPeriod {seconds},600").
//
// The profile (NewCodec; Profile):
//
//	checkCrc: true                 # default true; a packet whose CRC does not match is confirmed with the computed checksum, so the device sends it again
//	tagLengths: {"0x49": 1}        # lengths of tags this codec does not know (none by default)
//	namedCommands: {engineStop: "Out 1,0"}   # replace a named command's text (default above)
//	failureWords: [incorrect, error, unknown, invalid, wrong]   # default; an answer holding one fails the command
package galileosky

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/cB-Sigma/trackers/track"
)

// Packet headers.
const (
	HeadMain       = 0x01
	HeadConfirm    = 0x02
	HeadGarmin     = 0x06
	HeadPicture    = 0x07
	HeadCompressed = 0x08
)

// MaxText is the longest command text.
const MaxText = 255

// MaxPicture bounds a picture.
const MaxPicture = 8 << 20

// Named commands.
var (
	// Interval bounds the interval command of a profile template.
	Interval = track.IntervalRange{Min: 1, Max: 65535}
	// NamedActions are the named commands with a default text.
	NamedActions = []string{track.ActionEngineStop, track.ActionEngineResume, track.ActionLocate, track.ActionReboot}
)

var defaultNamed = map[string]string{
	track.ActionEngineStop:   "Out 0,0",
	track.ActionEngineResume: "Out 0,1",
	track.ActionLocate:       "Status",
	track.ActionReboot:       "Reset",
}

// Profile is the manufacturer-variation settings.
type Profile struct {
	// CheckCRC (default true) refuses packets whose CRC does not match.
	CheckCRC *bool `json:"checkCrc,omitempty"`
	// TagLengths gives tags this codec does not know a length in bytes
	// ("0x49": 1).
	TagLengths map[string]int `json:"tagLengths,omitempty"`
	// NamedCommands replaces the text of a named command ("" turns it
	// off), with {seconds} and {imei}.
	NamedCommands track.NamedTemplates `json:"namedCommands,omitempty"`
	// FailureWords are the words whose presence in an answer fails the
	// command.
	FailureWords []string `json:"failureWords,omitempty"`
}

type config struct {
	crc   bool
	extra map[byte]int
	named track.NamedTemplates
	fail  []string
}

// NewCodec validates a profile (empty for the defaults) and returns a
// factory of codecs, one per connection.
func NewCodec(raw json.RawMessage) (func() track.Codec, error) {
	var p Profile
	if err := track.StrictJSON(raw, &p); err != nil {
		return nil, err
	}
	if err := p.NamedCommands.Check(false); err != nil {
		return nil, err
	}
	c := config{crc: p.CheckCRC == nil || *p.CheckCRC, extra: map[byte]int{}, named: p.NamedCommands}
	for k, v := range p.TagLengths {
		n, err := strconv.ParseUint(strings.TrimPrefix(strings.ToLower(k), "0x"), 16, 8)
		if err != nil || !strings.HasPrefix(strings.ToLower(k), "0x") {
			return nil, fmt.Errorf("tagLengths: %q is not a tag number such as \"0x49\"", k)
		}
		if _, known := tagLength(byte(n)); known || variable(byte(n)) {
			return nil, fmt.Errorf("tagLengths: tag %s is already known", k)
		}
		if v < 1 || v > 255 {
			return nil, fmt.Errorf("tagLengths.%s: a length is 1 to 255 bytes", k)
		}
		c.extra[byte(n)] = v
	}
	fw, err := track.FailureWords(p.FailureWords, "incorrect", "error", "unknown", "invalid", "wrong")
	if err != nil {
		return nil, err
	}
	c.fail = fw
	return func() track.Codec { return &codec{cfg: c} }, nil
}

type codec struct {
	cfg      config
	imei     string
	deviceID uint16
	status   uint16 // the last status word, for alerts on change
	picture  []byte
}

// ---- framing ----------------------------------------------------------------

// CRC is CRC-16/MODBUS: reflected 0x8005, initial value 0xFFFF, sent
// little endian.
func CRC(b []byte) uint16 {
	c := uint16(0xFFFF)
	for _, v := range b {
		c ^= uint16(v)
		for range 8 {
			if c&1 != 0 {
				c = c>>1 ^ 0xA001
			} else {
				c >>= 1
			}
		}
	}
	return c
}

// Frame builds a 0x01 packet of these tags; archive sets the "archive
// holds more" flag.
func Frame(tags []byte, archive bool) []byte {
	n := uint16(len(tags))
	if archive {
		n |= 0x8000
	}
	out := []byte{HeadMain}
	out = binary.LittleEndian.AppendUint16(out, n)
	out = append(out, tags...)
	return binary.LittleEndian.AppendUint16(out, CRC(out))
}

// Confirm is the confirmation of a packet: 0x02 and its checksum.
func Confirm(packet []byte) []byte {
	if len(packet) < 2 {
		return nil
	}
	return append([]byte{HeadConfirm}, packet[len(packet)-2:]...)
}

// ErrCRC is a packet whose CRC does not match.
var ErrCRC = errors.New("galileosky: CRC mismatch")

// readPacket reads one packet whole: header, length, body, CRC.
func readPacket(r *bufio.Reader) (raw []byte, err error) {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:1]); err != nil {
		return nil, err
	}
	if hdr[0] == HeadConfirm {
		var b [2]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return nil, err
		}
		return []byte{hdr[0], b[0], b[1]}, nil
	}
	if _, err := io.ReadFull(r, hdr[1:]); err != nil {
		return nil, err
	}
	n := int(binary.LittleEndian.Uint16(hdr[1:]) & 0x7FFF)
	raw = make([]byte, 3+n+2)
	copy(raw, hdr[:])
	if _, err := io.ReadFull(r, raw[3:]); err != nil {
		return nil, err
	}
	if CRC(raw[:3+n]) != binary.LittleEndian.Uint16(raw[3+n:]) {
		return raw, ErrCRC
	}
	return raw, nil
}

// ReadFrame reads a packet (for simulators): its header and the bytes
// between the length and the CRC (a confirmation's body is the checksum).
func ReadFrame(r *bufio.Reader) (byte, []byte, error) {
	raw, err := readPacket(r)
	if err != nil {
		return 0, nil, err
	}
	if raw[0] == HeadConfirm {
		return raw[0], raw[1:], nil
	}
	return raw[0], raw[3 : len(raw)-2], nil
}

// ---- tags -------------------------------------------------------------------

// tagLength is the length of a fixed-length tag.
func tagLength(t byte) (int, bool) {
	switch {
	case t == 0x01, t == 0x02, t == 0x35, t == 0x43, t == 0xD5,
		t >= 0x88 && t <= 0x8C, t >= 0xA0 && t <= 0xAF, t >= 0xC4 && t <= 0xD2:
		return 1, true
	case t == 0x04, t == 0x10, t == 0x34, t == 0x40, t == 0x41, t == 0x42, t == 0x45, t == 0x46, t == 0x48,
		t >= 0x50 && t <= 0x59, t >= 0x60 && t <= 0x62, t >= 0x70 && t <= 0x77,
		t >= 0xB0 && t <= 0xB9, t >= 0xD6 && t <= 0xDA:
		return 2, true
	case t >= 0x63 && t <= 0x6F, t >= 0x80 && t <= 0x87, t == 0x5D, t == 0xFA:
		return 3, true
	case t == 0x20, t == 0x33, t == 0x44, t == 0x47, t == 0x5A, t == 0x90, t >= 0xC0 && t <= 0xC3, t == 0xD3, t == 0xD4,
		t >= 0xDB && t <= 0xDF, t >= 0xE0 && t <= 0xE9 && t != 0xE1, t >= 0xF0 && t <= 0xF9:
		return 4, true
	case t == 0xFD:
		return 8, true
	case t == 0x30:
		return 9, true
	case t == 0x03:
		return 15, true
	case t == 0x5C:
		return 68, true
	}
	return 0, false
}

// variable reports tags whose value starts with its own length.
func variable(t byte) bool { return t == 0xE1 || t == 0xEA || t == 0xFE }

type rec struct {
	r       track.Record
	tags    int
	hasData bool
}

func u16(b []byte) uint16 { return binary.LittleEndian.Uint16(b) }
func u32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }

// tag puts one tag's value into a record.
func (c *codec) tag(x *rec, t byte, v []byte, m *track.Message) {
	st := x.r.Status
	switch {
	case t >= 0x50 && t <= 0x57:
		st["in"+strconv.Itoa(int(t-0x50))] = int(u16(v))
	case t >= 0x60 && t <= 0x62:
		st["fuel"+strconv.Itoa(int(t-0x60))] = int(u16(v))
	case t >= 0x63 && t <= 0x6F:
		st["fuel"+strconv.Itoa(int(t-0x60))] = int(u16(v))
		st["fuelTemp"+strconv.Itoa(int(t-0x60))] = int(int8(v[2]))
	case t >= 0x70 && t <= 0x77:
		i := strconv.Itoa(int(t - 0x70))
		st["tempId"+i] = int(v[0])
		st["temp"+i] = int(int8(v[1]))
	case t >= 0x80 && t <= 0x87:
		i := strconv.Itoa(int(t - 0x80))
		st["humidityId"+i] = int(v[0])
		st["humidityTemp"+i] = int(int8(v[1]))
		st["humidity"+i] = math.Round(float64(v[2])*100/255*100) / 100
	case t >= 0x89 && t <= 0x8C:
		st["fuelSensorTemp"+strconv.Itoa(int(t-0x8A))] = int(int8(v[0]))
	case t >= 0xA0 && t <= 0xAF:
		st["can8BitR"+strconv.Itoa(int(t-0xA0+15))] = int(v[0])
	case t >= 0xB0 && t <= 0xB9:
		st["can16BitR"+strconv.Itoa(int(t-0xB0+5))] = int(u16(v))
	case t >= 0xC4 && t <= 0xD2:
		st["can8BitR"+strconv.Itoa(int(t-0xC4))] = int(v[0])
	case t >= 0xD6 && t <= 0xDA:
		st["can16BitR"+strconv.Itoa(int(t-0xD6))] = int(u16(v))
	case t >= 0xDB && t <= 0xDF:
		st["can32BitR"+strconv.Itoa(int(t-0xDB))] = u32(v)
	case t >= 0xF0 && t <= 0xF9:
		st["can32BitR"+strconv.Itoa(int(t-0xF0+5))] = u32(v)
	case t >= 0xE2 && t <= 0xE9:
		st["userData"+strconv.Itoa(int(t-0xE2))] = u32(v)
	default:
		c.tagOther(x, t, v, m)
	}
}

func (c *codec) tagOther(x *rec, t byte, v []byte, m *track.Message) {
	st := x.r.Status
	fix := func() *track.Fix {
		if x.r.Fix == nil {
			x.r.Fix = &track.Fix{}
		}
		return x.r.Fix
	}
	switch t {
	case 0x01:
		st["hardwareVersion"] = int(v[0])
	case 0x02:
		st["firmwareVersion"] = int(v[0])
	case 0x03:
		imei := strings.TrimRight(string(v), "\x00 ")
		m.IMEI = imei
		if c.imei == "" {
			m.Login = true
		}
		c.imei = imei
	case 0x04:
		c.deviceID = u16(v)
		st["deviceId"] = int(c.deviceID)
	case 0x10:
		st["recordNumber"] = int(u16(v))
	case 0x20:
		x.r.Time = time.Unix(int64(u32(v)), 0).UTC()
	case 0x30:
		f := fix()
		sats := int(v[0] & 0x0F)
		f.Sats = &sats
		f.Valid = v[0]>>4 == 0
		f.Lat = float64(int32(u32(v[1:5]))) / 1e6
		f.Lon = float64(int32(u32(v[5:9]))) / 1e6
		x.hasData = true
	case 0x33:
		f := fix()
		f.Speed = track.F(float64(u16(v)) / 10)
		f.Heading = track.F(float64(u16(v[2:])) / 10)
	case 0x34:
		fix().Alt = track.F(float64(int16(u16(v))))
	case 0x35:
		fix().HDOP = track.F(float64(v[0]) / 10)
	case 0x40:
		s := u16(v)
		st["statusWord"] = int(s)
		st["moving"] = s&1 != 0
		st["ignition"] = s&(1<<9) != 0
		st["gsmSignal"] = int(s>>12) & 3
		st["glonass"] = s&(1<<11) != 0
		st["externalVoltageLow"] = s&(1<<8) != 0
		st["insideGeofence"] = s&(1<<4) != 0
		rising := s &^ c.status
		c.status = s
		for _, a := range []struct {
			bit uint
			typ string
		}{{15, "emergency"}, {10, "impact"}, {1, "tilt"}, {6, "gnss-antenna-cut"}, {5, "low-battery"}} {
			if rising&(1<<a.bit) != 0 {
				x.r.Alerts = append(x.r.Alerts, track.NewAlert(a.typ, "status-bit-"+strconv.Itoa(int(a.bit))))
			}
		}
	case 0x41:
		st["externalVoltage"] = float64(u16(v)) / 1000
	case 0x42:
		st["batteryVoltage"] = float64(u16(v)) / 1000
	case 0x43:
		st["deviceTemp"] = int(int8(v[0]))
	case 0x44:
		a := u32(v)
		st["acceleration"] = map[string]any{"x": int(a & 0x3FF), "y": int(a >> 10 & 0x3FF), "z": int(a >> 20 & 0x3FF)}
	case 0x45:
		st["outputs"] = int(u16(v))
	case 0x46:
		st["inputs"] = int(u16(v))
	case 0x47:
		st["ecoDrive"] = map[string]any{"acceleration": int(v[0]), "braking": int(v[1]), "turn": int(v[2]), "bump": int(v[3])}
	case 0x48:
		st["statusExtended"] = int(u16(v))
	case 0x58, 0x59:
		st["rs232_"+strconv.Itoa(int(t-0x58))] = int(u16(v))
	case 0x88:
		st["rs232FuelTemp"] = int(int8(v[0]))
	case 0x90:
		st["driverId"] = strconv.FormatUint(uint64(u32(v)), 10)
	case 0xD3:
		st["driverId2"] = strconv.FormatUint(uint64(u32(v)), 10)
	case 0xC0:
		st["fuelUsed"] = float64(u32(v)) / 2
	case 0xC1:
		st["fuelLevel"] = float64(v[0]) * 4 / 10
		st["coolantTemp"] = int(v[1]) - 40
		st["rpm"] = float64(u16(v[2:])) / 8
	case 0xC2:
		st["canMileage"] = uint64(u32(v)) * 5
	case 0xC3:
		st["canB1"] = u32(v)
	case 0xD4:
		st["odometer"] = u32(v)
	case 0xD5:
		st["iButtonState"] = int(v[0])
	case 0xE0:
		st["commandNumber"] = u32(v)
	case 0xE1:
		st["answer"] = string(v)
	case 0xEA:
		st["userArray"] = hex.EncodeToString(v)
	case 0xFE:
		st["extendedTags"] = hex.EncodeToString(v)
	default:
		tags, _ := st["tags"].(map[string]any)
		if tags == nil {
			tags = map[string]any{}
			st["tags"] = tags
		}
		tags[fmt.Sprintf("0x%02x", t)] = hex.EncodeToString(v)
	}
	if t != 0x01 && t != 0x02 && t != 0x03 && t != 0x04 && t != 0xE0 && t != 0xE1 {
		x.hasData = true
	}
}

// ---- decoding ---------------------------------------------------------------

func (c *codec) Decode(r *bufio.Reader) (*track.Message, error) {
	raw, err := readPacket(r)
	var crcWarn *track.Warning
	if errors.Is(err, ErrCRC) {
		n := len(raw) - 2
		w := track.Warning{Code: "crcMismatch", Setting: "profile.checkCrc",
			Detail: fmt.Sprintf("CRC %04X, computed %04X", u16(raw[n:]), CRC(raw[:n])),
			Msg:    "A packet whose CRC does not match was confirmed with the computed checksum (the device sends it again). Set profile.checkCrc to false if the device computes it another way."}
		if c.cfg.crc {
			reply := binary.LittleEndian.AppendUint16([]byte{HeadConfirm}, CRC(raw[:n]))
			return nil, &track.Skip{Warning: w, Reply: reply}
		}
		crcWarn = &w
	} else if err != nil {
		return nil, err
	}
	var m *track.Message
	switch raw[0] {
	case HeadMain:
		m = c.main(raw)
	case HeadPicture:
		m, err = c.pictureMsg(raw)
		if err != nil {
			return nil, err
		}
	case HeadCompressed:
		return nil, &track.Skip{Warning: track.Warning{Code: "compressedPacket",
			Msg: "A compressed Galileosky packet was passed over unconfirmed: this codec does not read them. Set the device to the uncompressed protocol (command \"Protocol 0\")."}}
	case HeadGarmin:
		return nil, &track.Skip{Warning: track.Warning{Code: "garminFmi", Detail: fmt.Sprintf("% x", trim(raw[3:len(raw)-2])),
			Msg: "A Garmin FMI packet relayed by the device was passed over (it needs no confirmation)."}}
	default:
		return nil, &track.Skip{Warning: track.Warning{Code: "unknownMessage", Detail: fmt.Sprintf("header 0x%02x", raw[0]),
			Msg: "A Galileosky packet with a header this codec does not read was passed over."}}
	}
	if crcWarn != nil {
		m.Warnings = append(m.Warnings, *crcWarn)
	}
	if m.IMEI == "" {
		m.IMEI = c.imei
	}
	return m, nil
}

func trim(b []byte) []byte {
	if len(b) > 32 {
		return b[:32]
	}
	return b
}

func (c *codec) main(raw []byte) *track.Message {
	archive := raw[2]&0x80 != 0
	b := raw[3 : len(raw)-2]
	m := &track.Message{Kind: "normal", Reply: Confirm(raw)}
	var recs []*rec
	cur := &rec{r: track.Record{Status: map[string]any{}}}
	last := -1
	var answer *string
	var number *uint32
	for len(b) > 0 {
		t := b[0]
		b = b[1:]
		if int(t) <= last {
			recs = append(recs, cur)
			cur = &rec{r: track.Record{Status: map[string]any{}}}
		}
		last = int(t)
		var v []byte
		switch {
		case t == 0xE1 || t == 0xEA:
			if len(b) < 1 || len(b) < 1+int(b[0]) {
				b = nil
				m.Warnings = append(m.Warnings, truncated(t))
				continue
			}
			v, b = b[1:1+int(b[0])], b[1+int(b[0]):]
		case t == 0xFE:
			if len(b) < 2 || len(b) < 2+int(u16(b)) {
				b = nil
				m.Warnings = append(m.Warnings, truncated(t))
				continue
			}
			n := int(u16(b))
			v, b = b[2:2+n], b[2+n:]
		default:
			n, ok := tagLength(t)
			if !ok {
				n, ok = c.cfg.extra[t]
			}
			if !ok {
				m.Warnings = append(m.Warnings, track.Warning{Code: "unknownTag", Setting: "profile.tagLengths",
					Detail: fmt.Sprintf("tag 0x%02x", t),
					Msg:    fmt.Sprintf("A tag this codec does not know (0x%02x) ended the reading of its packet; what came before it was kept and the packet confirmed. Give its length in profile.tagLengths.", t)})
				b = nil
				continue
			}
			if len(b) < n {
				m.Warnings = append(m.Warnings, truncated(t))
				b = nil
				continue
			}
			v, b = b[:n], b[n:]
		}
		cur.tags++
		switch t {
		case 0xE0:
			n := u32(v)
			number = &n
		case 0xE1:
			s := string(v)
			answer = &s
		}
		c.tag(cur, t, v, m)
	}
	if cur.tags > 0 {
		recs = append(recs, cur)
	}
	if answer != nil {
		m.Kind = "response"
		m.Response = answer
		m.Failed = track.AnswerFailed(*answer, c.cfg.fail)
		if number != nil {
			m.Correlation = strconv.FormatUint(uint64(*number), 10)
		}
	}
	for _, x := range recs {
		delete(x.r.Status, "commandNumber")
		delete(x.r.Status, "answer")
		if !x.hasData && (len(x.r.Status) == 0 || answer != nil) {
			continue
		}
		if x.r.Time.IsZero() {
			x.r.Time = time.Now().UTC()
		}
		if x.r.Fix != nil {
			if x.r.Fix.Lat == 0 && x.r.Fix.Lon == 0 && x.r.Fix.Sats == nil {
				x.r.Fix = nil // speed or altitude without coordinates
			} else {
				x.r.Fix.Time = x.r.Time
			}
		}
		x.r.History = archive
		for _, a := range x.r.Alerts {
			if a.Type == "emergency" {
				m.Kind = "emergency"
			}
		}
		m.Records = append(m.Records, x.r)
	}
	if m.Login && m.Kind == "normal" {
		hasFix := false
		for _, r := range m.Records {
			hasFix = hasFix || r.Fix != nil
		}
		if !hasFix {
			m.Kind = "login"
		}
	}
	return m
}

func truncated(t byte) track.Warning {
	return track.Warning{Code: "truncatedTag", Detail: fmt.Sprintf("tag 0x%02x", t),
		Msg: "A packet ended inside a tag's value; what came before it was kept."}
}

func (c *codec) pictureMsg(raw []byte) (*track.Message, error) {
	body := raw[3 : len(raw)-2]
	m := &track.Message{Kind: "image", Reply: append([]byte{HeadPicture}, raw[len(raw)-2:]...)}
	if len(body) < 1 {
		return nil, &track.Skip{Warning: track.Warning{Code: "shortPacket", Msg: "A picture packet without its part number was passed over."}, Reply: m.Reply}
	}
	if len(body) == 1 {
		img := c.picture
		c.picture = nil
		if len(img) > 0 {
			m.Records = []track.Record{{Time: time.Now().UTC(), Status: map[string]any{"image": img}}}
		}
		return m, nil
	}
	if body[0] == 0 {
		c.picture = nil
	}
	if len(c.picture)+len(body)-1 > MaxPicture {
		c.picture = nil
		m.Warnings = append(m.Warnings, track.Warning{Code: "fileTooLarge", Msg: "A picture larger than the codec takes was dropped."})
		return m, nil
	}
	c.picture = append(c.picture, body[1:]...)
	return m, nil
}

// ---- commands ---------------------------------------------------------------

// CommandFrame builds a command packet: IMEI, device identifier, command
// number and text.
func CommandFrame(imei string, deviceID uint16, number uint32, text string) []byte {
	tags := append([]byte{0x03}, imei...)
	tags = append(tags, 0x04)
	tags = binary.LittleEndian.AppendUint16(tags, deviceID)
	tags = append(tags, 0xE0)
	tags = binary.LittleEndian.AppendUint32(tags, number)
	tags = append(tags, 0xE1, byte(len(text)))
	tags = append(tags, text...)
	return Frame(tags, false)
}

func (c *codec) Command(imei string, content any, seq uint32) ([]byte, bool, error) {
	if len(imei) != 15 {
		return nil, false, fmt.Errorf("galileosky: a command needs the device's 15-digit IMEI, not %q", imei)
	}
	text, err := c.text(imei, content)
	if err != nil {
		return nil, false, err
	}
	if len(text) > MaxText {
		return nil, false, fmt.Errorf("the command is %d characters; Galileosky commands take at most %d", len(text), MaxText)
	}
	return CommandFrame(imei, c.deviceID, seq, text), true, nil
}

func (c *codec) text(imei string, content any) (string, error) {
	n, named, err := track.ReadNamed(content)
	if err != nil {
		return "", err
	}
	if !named {
		return track.CommandText(content)
	}
	if _, own := c.cfg.named[n.Action]; !own && n.Action == track.ActionInterval {
		return "", track.Unsupported("galileosky", n.Action,
			"WrPeriod sets the moving and parked periods together; set profile.namedCommands.interval, for example \"WrPeriod {seconds},600\"")
	}
	return track.NamedText("galileosky", n, c.cfg.named, defaultNamed, Interval, imei, "")
}

// Correlation: the answer carries the command number, which is the
// sequence number.
func (c *codec) Correlation(_ any, seq uint32) (string, bool) {
	return strconv.FormatUint(uint64(seq), 10), true
}
