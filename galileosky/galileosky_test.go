// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package galileosky_test

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/trackers/galileosky"
	"github.com/cB-Sigma/trackers/track"
)

func h(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

// Packets captured from devices, as published in Traccar's decoder tests
// (Apache-2.0, see NOTICE).
const (
	// Head and data tags in one packet, one record.
	devFull = "011801018202130338363833343530333230343234323604640010a406207caa9f5b300c830a7901ca0ec802330000000034b802350540003e41703f422b1043234504004600e09000000000a000a100a200a300a400a500a600a700a800a900aa00ab00ac00ad00ae00af00b00000b10000b20000b30000b40000b50000b60000b70000b80000b90000c000000000c100000000c200000000c300000000c400c500c600c700c800c900ca00cb00cc00cd00ce00cf00d000d100d200d4d3140000d60000d70000d80000d90000da0000db00000000dc00000000dd00000000de00000000df00000000f000000000f100000000f200000000f300000000f400000000f500000000f600000000f700000000f800000000f9000000008960"
	// Five records, each with the head tags; archive flag set.
	devFive = "017583018202120338363833343530333230363635373304520010384520c850975b300cc03a910107cbf9023365000607341300350640012a41236a4215104329450400460020500000510000520000530000540000550000c000000000c100000000c44bc500c6ffc700c800c900ca00cb00d4993b0500d64100d70000d8be02d90000da0000db00000000dc00000000dd00000000de00000000df00000000f000000000f100000000f200000000f300000000018202120338363833343530333230363635373304520010394520c950975b300cab3a91010ecbf902336000be06341300350640012a41266a4216104329450400460020500000510000520000530000540000550000c000000000c100000000c44bc500c6ffc700c800c900ca00cb00d49b3b0500d64100d70000d8bc02d90000da0000db00000000dc00000000dd00000000de00000000df00000000f000000000f100000000f200000000f3000000000182021203383638333435303332303636353733045200103a4520ca50975b300c953a910113cbf9023358008f06341300350640012a41206a4215104329450400460020500000510000520000530000540000550000c000000000c100000000c44bc500c6ffc700c800c900ca00cb00d49e3b0500d64100d70000d8ba02d90000da0000db00000000dc00000000dd00000000de00000000df00000000f000000000f100000000f200000000f3000000000182021203383638333435303332303636353733045200103b45204251975b300c6d3a91011dcbf9023300008a06341300350640013a41726a4216104329450400460020500000510000520000530000540000550000c000000000c100000000c44bc500c6ffc700c800c900ca00cb00d4a33b0500d64800d70000d80003d90000da0000db00000000dc00000000dd00000000de00000000df00000000f000000000f100000000f200000000f3000000000182021203383638333435303332303636353733045200103c4520bb51975b300c6d3a91011dcbf9023300008a06341300350640013a41816a4216104329450400460020500000510000520000530000540000550000c000000000c100000000c44bc500c6ffc700c800c900ca00cb00d4a33b0500d64800d70000d80003d90000da0000db00000000dc00000000dd00000000de00000000df00000000f000000000f100000000f200000000f300000000e007"
	// Command answers.
	devAnswerInall = "01560003383636303530303338343337353836044701e000000000e13c494e414c4c3a696e303d31313230362c696e313d302c696e323d302c696e333d302c696e343d302c696e353d302c4163633d3536363932343732353bfdef"
	devAnswerOut   = "012a0003383633353931303233353137333732046600e000000000e1104f555428332e2e3029203d2031313130bb29"
	// A head packet: IMEI and device identifier.
	devHead = "011380033836383230343030313534393038370432008590"
	// Records with the user data array tag (0xEA).
	devUserArray = "01bf83043200101ee4209832bc62300549589302511aaa013300002e00342e02350440003b41b15d42d50e4326450e0046040050000051000052fc5c5300006100008b009000000000d400000000e201000000e376000000e4efce0100e53b590200e600000000e773000000e800000000e9a002d007ea140000d6021b00f8430220ac760000000000000000043200101de4201232bc62300549589302511aaa013300002e00342e02350440012b41b55d42d40e4326450e0046040050000051000052145d5300006100008b009000000000d400000000e201000000e376000000e4efce0100e53b590200e600000000e773000000e800000000e9a002d007ea140000d6021b00f8430220ac760000000000000000043200101ce4208e2ebc62300549589302511aaa013300002e00342e02350440013b41a95d42cd0e4325450f0046040050000051000052235d5300006100008b009000000000d400000000e201000000e376000000e4efce0100e53b590200e600000000e773000000e802000000e9a002d007ea140000d6021b00f8430220ac760000000000000000043200101be4208b2ebc62300549589302511aaa013300002e00342e02350440013b41a45d42cd0e432545090046040050000051000052115d5300006100008b009000000000d400000000e201000000e375000000e48ac90100e53a590200e673000000e773000000e806000000e9a002d007ea140000d6021b00f8430220ac760000000000000000043200101ae420642ebc62300549589302511aaa013300002e00342e02350440013b419f5d42cd0e4324450b00460600500000519313521c5d5300006100008b009000000000d400000000e201000000e300000000e406000000e5c5580200e673000000e700000000e801000000e9a002d007ea140000d6021b00f8430220ac7600000000000000000432001019e420632ebc62300549589302511aaa013300002e00342e02350440013b41725d42cd0e4324450b0046060050000051ab1352035d5300006100008b009000000000d400000000e201000000e300000000e406000000e5c5580200e673000000e700000000e8d6021b00e9a002d007ea140000d6021b00f8430220ac7600000000000000000432001018e4205c2ebc62300549589302511aaa013300002e00342e02350440013b41955d42cd0e4324450a00460400500000510000520b5d5300006100008b009000000000d400000000e201000000e30d000000e4a4350000e5c5580200e600000000e700000000e8d6021b00e9a002d007ea140000d6021b00f8430220ac76000000000000000099f3"
	// Records with the extended tags (0xFE).
	devExtended = "01ba83106c022016427763300694c274028f8251043300000000345c05351840002a41086842da0e43194600004700000000500000d4915b0000fe300021004d03000022000b0000002300230000002400a8ffffff25000700000026000c0000002700230000002800a8ffffff106b0220fb417763300551c27402ba8251043332000000345d05352740012a41786842da0e43194600004700000000500000d4895b0000fe300021004d03000022000b0000002300230000002400a8ffffff25000700000026000c0000002700230000002800a8ffffff106a0220fa41776330054cc27402bf825104333b005f02345d05352740012a417e6842da0e43194600004700000000500000d4895b0000fe300021004d03000022000b0000002300230000002400a8ffffff25000700000026000c0000002700230000002800a8ffffff10690220eb4177633006ffc17402ff8051043300000000343905351840012a419f6842da0e43194600004700000000500000d4515b0000fe300021004d03000022000b0000002300230000002400a8ffffff25000700000026000b0000002700230000002800acffffff10680220af4177633006ffc17402ff8051043300000000343905351840092a413e6a42db0e43194600004700000000500101d4515b0000fe300021004d03000022000b0000002300230000002400a8ffffff25000700000026000b0000002700230000002800aaffffff10670220ac4177633006ffc17402ff8051043300000000343905351840092a41dd6942db0e43194601004701000200501269d4515b0000fe300021004d03000022000b0000002300230000002400a8ffffff25000700000026000b0000002700230000002800aaffffff106602208e417763300603c27402fc8051043337000000343905351840092a41826d42da0e431946010047000b050750a56cd4515b0000fe300021004d03000022000b0000002300230000002400a8ffffff25000700000026000b0000002700230000002800adffffff106502208b4177633005fec17402f38051043362008c01343905352640092a416e6d42da0e431946010047080a160750d96cd44c5b0000fe300021004d03000022000b0000002300230000002400a8ffffff25000700000026000b0000002700230000002800adffffff106402208241776330060cc174021480510433c6002301343505351840092a41966d42da0e4319460100470a000a0550c26cd4235b0000fe300021004d03000022000b0000002300230000002400aaffffff25000700000026000b0000002700230000002800adffffff6121"
)

func newCodec(t *testing.T, profile string) track.Codec {
	t.Helper()
	nc, err := galileosky.NewCodec(json.RawMessage(profile))
	if err != nil {
		t.Fatal(err)
	}
	return nc()
}

func decodeAll(c track.Codec, frames ...[]byte) ([]*track.Message, []error) {
	br := bufio.NewReader(bytes.NewReader(bytes.Join(frames, nil)))
	var out []*track.Message
	var errs []error
	for {
		m, err := c.Decode(br)
		if err == io.EOF {
			return out, errs
		}
		if err != nil {
			errs = append(errs, err)
			if !errors.Is(err, track.ErrSkip) {
				return out, errs
			}
			continue
		}
		out = append(out, m)
	}
}

func one(t *testing.T, c track.Codec, frame []byte) *track.Message {
	t.Helper()
	ms, errs := decodeAll(c, frame)
	if len(errs) != 0 || len(ms) != 1 {
		t.Fatalf("%v %v", ms, errs)
	}
	return ms[0]
}

func near(a, b float64) bool { return a-b < 1e-6 && b-a < 1e-6 }

// ack is the confirmation: 0x02 and the packet's checksum.
func ack(frame []byte) []byte { return append([]byte{0x02}, frame[len(frame)-2:]...) }

func TestCRC(t *testing.T) {
	// CRC-16/MODBUS check value.
	if galileosky.CRC([]byte("123456789")) != 0x4B37 {
		t.Fatal("crc")
	}
	for _, v := range []string{devFull, devFive, devAnswerInall, devAnswerOut, devHead, devUserArray, devExtended} {
		b := h(v)
		if galileosky.CRC(b[:len(b)-2]) != binary.LittleEndian.Uint16(b[len(b)-2:]) {
			t.Fatalf("%s…", v[:16])
		}
	}
}

func TestHeadAndData(t *testing.T) {
	c := newCodec(t, "")
	m := one(t, c, h(devFull))
	if !m.Login || m.IMEI != "868345032042426" || !bytes.Equal(m.Reply, ack(h(devFull))) || len(m.Records) != 1 {
		t.Fatalf("%+v", m)
	}
	r := m.Records[0]
	f := r.Fix
	if f == nil || !f.Valid || *f.Sats != 12 || !near(f.Lat, 24.709763) || !near(f.Lon, 46.665418) ||
		!f.Time.Equal(time.Unix(0x5b9faa7c, 0).UTC()) || *f.Alt != 696 || *f.HDOP != 0.5 || *f.Speed != 0 {
		t.Fatalf("%+v", f)
	}
	st := r.Status
	if st["hardwareVersion"] != 130 || st["firmwareVersion"] != 19 || st["deviceId"] != 100 || st["recordNumber"] != 1700 ||
		st["externalVoltage"] != 16.24 || st["batteryVoltage"] != 4.139 || st["deviceTemp"] != 35 || st["ignition"] != true ||
		st["gsmSignal"] != 3 || st["odometer"] != uint32(0x14d3) || st["outputs"] != 4 || st["inputs"] != 0xe000 {
		t.Fatalf("%+v", st)
	}
	if len(r.Alerts) != 1 || r.Alerts[0].Type != "impact" {
		t.Fatalf("%+v", r.Alerts)
	}
	// The same state again raises nothing (alerts are on change).
	m = one(t, c, h(devFull))
	if m.Login || len(m.Records[0].Alerts) != 0 {
		t.Fatalf("%+v", m)
	}
}

func TestSeveralRecords(t *testing.T) {
	m := one(t, newCodec(t, ""), h(devFive))
	if len(m.Records) != 5 || !m.Records[0].History || m.IMEI != "868345032066573" {
		t.Fatalf("%d %+v", len(m.Records), m)
	}
	for i, r := range m.Records {
		if r.Fix == nil || r.Status["recordNumber"] != 0x4538+i {
			t.Fatalf("%d %+v", i, r)
		}
	}
	m = one(t, newCodec(t, ""), h(devUserArray))
	if len(m.Records) != 7 || m.Records[0].Status["userData0"] != uint32(1) || m.Records[0].Status["userArray"] != "0000d6021b00f8430220ac760000000000000000" {
		t.Fatalf("%d %+v", len(m.Records), m.Records[0].Status)
	}
	m = one(t, newCodec(t, ""), h(devExtended))
	if len(m.Records) != 9 || m.Records[0].Status["extendedTags"] == nil {
		t.Fatalf("%d %+v", len(m.Records), m.Records[0].Status)
	}
	// Speed and course: tenths.
	if f := m.Records[1].Fix; *f.Speed != 5 || *f.Heading != 0 {
		t.Fatalf("%+v", f)
	}
}

func TestHeadOnly(t *testing.T) {
	m := one(t, newCodec(t, ""), h(devHead))
	if !m.Login || m.IMEI != "868204001549087" || m.Kind != "login" || !m.Records[0].History {
		t.Fatalf("%+v", m)
	}
}

// A packet built from the examples in Galileosky's tag table (coordinates,
// speed and direction).
func TestDocExamples(t *testing.T) {
	var tags []byte
	tags = append(tags, 0x03)
	tags = append(tags, "861230043907626"...)
	tags = append(tags, 0x20, 0x00, 0x2F, 0x0E, 0x6A)
	tags = append(tags, 0x30, 0x07, 0xC0, 0x0E, 0x32, 0x03, 0xB8, 0xD7, 0x2D, 0x05)
	tags = append(tags, 0x33, 0x5C, 0x00, 0x48, 0x08)
	tags = append(tags, 0x70, 0x01, 0x10)
	tags = append(tags, 0x80, 0x01, 0x10, 0x20)
	tags = append(tags, 0xC1, 0xFA, 0x72, 0x50, 0x25)
	frame := galileosky.Frame(tags, false)
	m := one(t, newCodec(t, ""), frame)
	r := m.Records[0]
	f := r.Fix
	if !f.Valid || *f.Sats != 7 || !near(f.Lat, 53.612224) || !near(f.Lon, 86.890424) || !near(*f.Speed, 9.2) || !near(*f.Heading, 212) {
		t.Fatalf("%+v", f)
	}
	if r.Status["temp0"] != 16 || r.Status["humidity0"] != 12.55 || r.Status["fuelLevel"] != 100.0 || r.Status["coolantTemp"] != 74 || r.Status["rpm"] != 1194.0 {
		t.Fatalf("%+v", r.Status)
	}
}

func TestCommands(t *testing.T) {
	c := newCodec(t, "")
	_ = one(t, c, h(devFull))
	b, answers, err := c.Command("868345032042426", map[string]any{"text": "Status"}, 0x01020304)
	if err != nil || !answers {
		t.Fatal(err)
	}
	want := []byte{0x01, 0x20, 0x00, 0x03}
	want = append(want, "868345032042426"...)
	want = append(want, 0x04, 0x64, 0x00, 0xE0, 0x04, 0x03, 0x02, 0x01, 0xE1, 6)
	want = append(want, "Status"...)
	want = binary.LittleEndian.AppendUint16(want, galileosky.CRC(want))
	if !bytes.Equal(b, want) {
		t.Fatalf("% x\n% x", b, want)
	}
	corr, strict := c.(track.Correlator).Correlation(map[string]any{"text": "Status"}, 0x01020304)
	if corr != "16909060" || !strict {
		t.Fatal(corr)
	}
	m := one(t, c, h(devAnswerOut))
	if m.Response == nil || *m.Response != "OUT(3..0) = 1110" || m.Correlation != "0" || m.Kind != "response" || m.Failed ||
		!bytes.Equal(m.Reply, ack(h(devAnswerOut))) {
		t.Fatalf("%+v", m)
	}
	m = one(t, newCodec(t, ""), h(devAnswerInall))
	if m.Response == nil || !strings.HasPrefix(*m.Response, "INALL:in0=11206") || m.IMEI != "866050038437586" {
		t.Fatalf("%+v", m)
	}
	for _, tc := range []struct {
		action map[string]any
		text   string
	}{
		{map[string]any{"action": "engineStop"}, "Out 0,0"},
		{map[string]any{"action": "engineResume"}, "Out 0,1"},
		{map[string]any{"action": "locate"}, "Status"},
		{map[string]any{"action": "reboot"}, "Reset"},
	} {
		b, _, err := c.Command("868345032042426", tc.action, 1)
		if err != nil || !bytes.HasSuffix(b[:len(b)-2], append([]byte{byte(len(tc.text))}, tc.text...)) {
			t.Fatalf("%v: %q %v", tc.action, b, err)
		}
	}
	if _, _, err := c.Command("868345032042426", map[string]any{"action": "interval", "seconds": 30.0}, 1); !errors.Is(err, track.ErrUnsupported) {
		t.Fatal(err)
	}
	c2 := newCodec(t, `{"namedCommands": {"interval": "WrPeriod {seconds},600"}}`)
	b, _, err = c2.Command("868345032042426", map[string]any{"action": "interval", "seconds": 30.0}, 1)
	if err != nil || !bytes.Contains(b, []byte("WrPeriod 30,600")) {
		t.Fatalf("%q %v", b, err)
	}
	if _, _, err := c.Command("123", "Status", 1); err == nil {
		t.Fatal("short IMEI accepted")
	}
	if _, _, err := c.Command("868345032042426", strings.Repeat("x", 256), 1); err == nil {
		t.Fatal("long text accepted")
	}
	// A device that answers with a failure word fails the command.
	tags := append([]byte{0x03}, "868345032042426"...)
	tags = append(tags, 0xE0, 1, 0, 0, 0, 0xE1, 17)
	tags = append(tags, "INCORRECT COMMAND"...)
	m = one(t, c, galileosky.Frame(tags, false))
	if !m.Failed || m.Correlation != "1" {
		t.Fatalf("%+v", m)
	}
}

func TestBadPackets(t *testing.T) {
	bad := h(devHead)
	bad[len(bad)-1] ^= 0xFF
	ms, errs := decodeAll(newCodec(t, ""), bad, h(devHead))
	var sk *track.Skip
	if len(errs) != 1 || !errors.As(errs[0], &sk) || sk.Code != "crcMismatch" || len(ms) != 1 {
		t.Fatalf("%v %v", ms, errs)
	}
	// checkCrc false takes it.
	m := one(t, newCodec(t, `{"checkCrc": false}`), bad)
	if !m.Login || len(m.Warnings) != 1 {
		t.Fatalf("%+v", m)
	}
	// An unknown tag ends the packet's reading; it is still acknowledged
	// (the device would send it forever), with the warning unknownTag and
	// what was read before it.
	tags := append([]byte{0x03}, "868345032042426"...)
	tags = append(tags, 0x20, 0x00, 0x2F, 0x0E, 0x6A, 0x49, 0x01)
	frame := galileosky.Frame(tags, false)
	m = one(t, newCodec(t, ""), frame)
	if len(m.Warnings) != 1 || m.Warnings[0].Code != "unknownTag" || !bytes.Equal(m.Reply, ack(frame)) || m.Records[0].Time.Unix() != 0x6A0E2F00 {
		t.Fatalf("%+v", m)
	}
	// A profile gives the tag its length.
	m = one(t, newCodec(t, `{"tagLengths": {"0x49": 1}}`), frame)
	if len(m.Warnings) != 0 || m.Records[0].Status["tags"].(map[string]any)["0x49"] != "01" {
		t.Fatalf("%+v", m)
	}
	// Compressed packets are passed over, unacknowledged.
	comp := []byte{0x08, 0x02, 0x00, 0xAA, 0xBB}
	comp = binary.LittleEndian.AppendUint16(comp, galileosky.CRC(comp))
	_, errs = decodeAll(newCodec(t, ""), comp)
	if len(errs) != 1 || !errors.As(errs[0], &sk) || sk.Code != "compressedPacket" {
		t.Fatalf("%v", errs)
	}
	for _, p := range []string{`{"x": 1}`, `{"tagLengths": {"0x30": 2}}`, `{"tagLengths": {"zz": 2}}`, `{"namedCommands": {"fly": "x"}}`} {
		if _, err := galileosky.NewCodec(json.RawMessage(p)); err == nil {
			t.Fatalf("%s accepted", p)
		}
	}
}

func TestPicture(t *testing.T) {
	part := func(n byte, data []byte) []byte {
		b := []byte{0x07}
		b = binary.LittleEndian.AppendUint16(b, uint16(len(data)+1))
		b = append(b, n)
		b = append(b, data...)
		return binary.LittleEndian.AppendUint16(b, galileosky.CRC(b))
	}
	c := newCodec(t, "")
	p0, p1, end := part(0, []byte{0xFF, 0xD8}), part(1, []byte{0xFF, 0xD9}), part(2, nil)
	ms, errs := decodeAll(c, h(devHead), p0, p1, end)
	if len(errs) != 0 || len(ms) != 4 {
		t.Fatalf("%v %v", ms, errs)
	}
	if !bytes.Equal(ms[1].Reply, append([]byte{0x07}, p0[len(p0)-2:]...)) || len(ms[1].Records) != 0 {
		t.Fatalf("%+v", ms[1])
	}
	if img := ms[3].Records[0].Status["image"].([]byte); !bytes.Equal(img, []byte{0xFF, 0xD8, 0xFF, 0xD9}) || ms[3].IMEI != "868204001549087" {
		t.Fatalf("%+v", ms[3])
	}
}

func TestFrame(t *testing.T) {
	f := galileosky.Frame([]byte{0x01, 0x82}, true)
	if !bytes.Equal(f[:5], []byte{0x01, 0x02, 0x80, 0x01, 0x82}) || galileosky.CRC(f[:5]) != binary.LittleEndian.Uint16(f[5:]) {
		t.Fatalf("% x", f)
	}
	head, body, err := galileosky.ReadFrame(bufio.NewReader(bytes.NewReader(f)))
	if err != nil || head != 0x01 || !bytes.Equal(body, []byte{0x01, 0x82}) {
		t.Fatalf("%x % x %v", head, body, err)
	}
	if len(galileosky.NamedActions) != 4 {
		t.Fatal(galileosky.NamedActions)
	}
}
