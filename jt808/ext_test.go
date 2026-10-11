// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package jt808_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/trackers/jt808"
	"github.com/cB-Sigma/trackers/track"
)

// A location with an ADAS item (0x64, pedestrian collision warning, alarm
// 11, five attachments), from Traccar's Jt808ProtocolDecoderTest
// (Apache-2.0; see NOTICE), quoted there without escaping, and one whose
// 0x66 is a vendor's cell item.
const (
	vADAS       = "7E020000834EB6FB4AF2C1010F00000800000C000B01AAB48204EA7E57000801AD00B626032715524501040000045130011F310112EB095554432D30343A3030140400000001150400000004642F0000000B00040100000000002A000801AAB33804EA7E542603271552450400303037343234322603271552450B0500E81120050E200102008C0006010400070200069B7E"
	vVendor0x66 = "7e02000072440061018577001b0000100000200066005ffb8b065dc8900000000000002309080513406316cd91fe1314da1080318122c3a19a6f6f3a0fc6318113660b01fe00000a069a011704de690201a16a011f6b010a6c0f35313031303139313539323738373571143839363231303030313931353932373837353546407e"
)

var phone13 = jt808.PhoneBCD("013511221122", 6)

func frame(id uint16, serial uint16, body []byte) string {
	return hex.EncodeToString(jt808.Encode(jt808.Header{ID: id, Version: -1, Phone: phone13, Serial: serial}, body))
}

func pad(s string, n int) []byte {
	b := make([]byte, n)
	copy(b, s)
	return b
}

// basic is a 28-byte location block at 12.97 N 77.59 E.
func basic() []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b[4:], jt808.StPositioned)
	b = binary.BigEndian.AppendUint32(b, 12970000)
	b = binary.BigEndian.AppendUint32(b, 77590000)
	b = append(b, 0, 0, 0, 100, 0, 90)
	return append(b, 0x26, 0x10, 0x11, 0x12, 0x00, 0x00)
}

// posBlock is the 19-byte position block of a safety item.
var posBlock = make([]byte, 19)

func safetyLabel() []byte {
	return append(append(pad("T000001", 7), 0x26, 0x10, 0x11, 0x12, 0x00, 0x00), 3, 2, 0)
}

func item(id byte, v []byte) []byte { return append([]byte{id, byte(len(v))}, v...) }

// JT/T 808-2011 registrations (8-byte model) are read by their length,
// a long plate included; the 2013 vector stays 2013.
func TestRegistration2011(t *testing.T) {
	reg := func(plate string) []byte {
		b := []byte{0x00, 0x1D, 0x01, 0x2C}
		b = append(b, pad("ACME", 5)...)
		b = append(b, pad("M-2011", 8)...)
		b = append(b, pad("1234567", 7)...)
		return append(append(b, 2), plate...)
	}
	ms := decodeAll(t, codec(t, ""), frame(0x0100, 1, reg("KA01AB1234")), frame(0x0100, 2, reg("KA01AB12345678")), vRegister2013)
	for i, m := range ms[:2] {
		st := m.Records[0].Status
		if st["protocolVersion"] != "2011" || st["model"] != "M-2011" || st["terminalId"] != "1234567" || st["plateColor"] != 2 || !m.Login || m.Reply == nil {
			t.Errorf("2011 registration %d: %v", i, st)
		}
	}
	if ms[1].Records[0].Status["plate"] != "KA01AB12345678" {
		t.Errorf("long plate %v", ms[1].Records[0].Status)
	}
	if st := ms[2].Records[0].Status; st["protocolVersion"] != "2013" || st["model"] != "HB-R03GBD" {
		t.Errorf("2013 registration %v", st)
	}
}

// Active safety items: the published ADAS item, DSM start and end, a
// tyre pressure item, a blind spot item, and a vendor 0x66 kept as hex.
func TestActiveSafetyItems(t *testing.T) {
	// The published ADAS frame is quoted unescaped (0x7E inside it) and
	// its check code does not match.
	raw := h(vADAS)
	adas := append(append([]byte{0x7E}, jt808.Escape(raw[1:len(raw)-1])...), 0x7E)
	ms := decodeAll(t, codec(t, `{"checkCrc": false}`), hex.EncodeToString(adas), vVendor0x66)
	if len(ms) != 2 || ms[0] == nil || len(ms[0].Records) != 1 {
		t.Fatalf("decoded %+v", ms[0])
	}
	rec := ms[0].Records[0]
	// The frame's alarm word also has bit 11 (camera fault).
	if len(rec.Alerts) != 2 || rec.Alerts[0].Type != "camera-fault" || rec.Alerts[1] != (track.Alert{Type: "pedestrian-collision-warning", Severity: track.Minor, Code: "0x64-0x04#11"}) {
		t.Fatalf("ADAS alerts %+v", rec.Alerts)
	}
	st := rec.Status
	if st["adasLabel"] != "303037343234322603271552450B0500" || st["adasTerminal"] != "0074242" || st["adasAttachments"] != 5 || st["adasState"] != "event" || st["adasLevel"] != 1 {
		t.Fatalf("ADAS status %v", st)
	}
	if _, kept := ms[1].Records[0].Status["item0x66"]; !kept {
		t.Fatalf("vendor 0x66 %v", ms[1].Records[0].Status)
	}

	dsm := func(state byte) []byte {
		v := binary.BigEndian.AppendUint32(nil, 77)
		v = append(v, state, 0x02, 2, 0, 0, 0, 0, 0)
		return item(0x65, append(append(v, posBlock...), safetyLabel()...))
	}
	tpms := binary.BigEndian.AppendUint32(nil, 78)
	tpms = append(append(append(tpms, 1), posBlock...), safetyLabel()...)
	tpms = append(tpms, 1, 3, 0x00, 0x02, 0x00, 180, 0x00, 41, 0x00, 90) // tyre 3: pressure low, 180 kPa, 41 °C, 90 %
	bsd := binary.BigEndian.AppendUint32(nil, 79)
	bsd = append(append(append(bsd, 1, 0x02), posBlock...), safetyLabel()...)
	loc1 := append(append(append(basic(), dsm(1)...), item(0x66, tpms)...), item(0x67, bsd)...)
	loc2 := append(basic(), dsm(2)...)
	ms = decodeAll(t, codec(t, ""), frame(0x0200, 1, loc1), frame(0x0200, 2, loc2))
	got := map[string]track.Alert{}
	for _, a := range ms[0].Records[0].Alerts {
		got[a.Type] = a
	}
	if len(got) != 3 || got["phone-use"].Severity != track.Major || got["phone-use"].Code != "0x65-0x02#77" ||
		got["tyre-pressure-low"].Code != "0x66-tyre3-bit1#78" || got["blind-spot-left-rear"].Code != "0x67-0x02#79" {
		t.Fatalf("safety alerts %+v", ms[0].Records[0].Alerts)
	}
	st = ms[0].Records[0].Status
	if st["tyre3Pressure"] != 180 || st["tyre3Temperature"] != 41 || st["dsmState"] != "start" || st["dsmAttachments"] != 2 || st["bsdAlarm"] != 2 {
		t.Fatalf("safety status %v", st)
	}
	if r := ms[1].Records[0]; len(r.Alerts) != 0 || r.Status["dsmState"] != "end" {
		t.Fatalf("DSM end %+v", r)
	}
}

// The alarm attachment messages are answered as a platform does (0x8001,
// 0x8001, 0x9212 with no pieces to send again), attachment data packets
// are passed over with one warning per file, and 0x9208 is framed.
func TestAttachmentMessages(t *testing.T) {
	lb := safetyLabel()
	b := append(pad("T000001", 7), lb...)
	b = append(b, pad("ALARM-1", 32)...)
	b = append(b, 0, 2)
	b = append(append(b, 9), "00_65.jpg"...)
	b = binary.BigEndian.AppendUint32(b, 1024)
	b = append(append(b, 9), "00_65.mp4"...)
	b = binary.BigEndian.AppendUint32(b, 4096)
	info := append(append([]byte{9}, "00_65.jpg"...), 0)
	info = binary.BigEndian.AppendUint32(info, 1024)
	data := append([]byte("01cd"), pad("00_65.jpg", 50)...)
	data = binary.BigEndian.AppendUint32(data, 0)
	data = binary.BigEndian.AppendUint32(data, 5)
	data = append(data, 0x7E, 1, 2, 3, 4)
	data2 := append([]byte(nil), data...)
	ms := decodeAll(t, codec(t, `{"strictAuth": true}`), frame(0x1210, 1, b), frame(0x1211, 2, info), hex.EncodeToString(data), hex.EncodeToString(data2), frame(0x1212, 3, info))
	if len(ms) != 5 || ms[2] != nil || ms[3] != nil {
		t.Fatalf("decoded %v", ms)
	}
	st := ms[0].Records[0].Status
	files, _ := st["attachmentFiles"].([]any)
	if st["attachmentAlarm"] != "ALARM-1" || len(files) != 2 || st["attachmentLabel"] != strings.ToUpper(hex.EncodeToString(lb)) {
		t.Fatalf("0x1210 %v", st)
	}
	if a := frameOf(t, ms[0].Reply); a.ID != jt808.MPlatformResponse || a.Body[4] != 0 {
		t.Fatalf("0x1210 answer %+v", a)
	}
	if ms[1].Records[0].Status["attachmentFile"] != "00_65.jpg" || frameOf(t, ms[1].Reply).ID != jt808.MPlatformResponse {
		t.Fatalf("0x1211 %+v", ms[1])
	}
	if a := frameOf(t, ms[4].Reply); a.ID != jt808.MFileDoneAnswer || !bytes.Equal(a.Body, append(append([]byte{9}, "00_65.jpg"...), 0, 0, 0)) {
		t.Fatalf("0x9212 % X", a.Body)
	}

	f, err := commandFrame(t, "", false, map[string]any{"op": "attachmentUpload", "server": "10.0.0.5", "tcpPort": 7612,
		"alarmLabel": hex.EncodeToString(lb), "alarmNumber": "ALARM-1"}, 7)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]byte{8}, "10.0.0.5"...)
	want = append(want, 0x1D, 0xBC, 0, 0)
	want = append(append(append(want, lb...), pad("ALARM-1", 32)...), make([]byte, 16)...)
	if f.ID != jt808.MAttachmentUpload || !bytes.Equal(f.Body, want) {
		t.Fatalf("0x9208 % X", f.Body)
	}
}

// JT/T 1078 signalling: the command bytes of every op, refusals, and the
// answers 0x1003 and 0x1205 correlated with their commands.
func TestVideoSignalling(t *testing.T) {
	srv := append([]byte{8}, "10.0.0.9"...)
	srv = append(srv, 0x04, 0x57, 0x04, 0x58) // tcp 1111, udp 1112
	start := "2026-10-11T08:00:00+05:30"
	startBCD := []byte{0x26, 0x10, 0x11, 0x10, 0x30, 0x00} // in +08:00
	for _, c := range []struct {
		content map[string]any
		id      uint16
		body    []byte
	}{
		{map[string]any{"op": "avAttributes"}, 0x9003, nil},
		{map[string]any{"op": "live", "server": "10.0.0.9", "tcpPort": 1111, "udpPort": 1112, "channel": 2, "data": "video", "stream": "sub"}, 0x9101, append(append([]byte(nil), srv...), 2, 1, 1)},
		{map[string]any{"op": "liveControl", "channel": 2, "control": "close", "close": "audio"}, 0x9102, []byte{2, 0, 1, 0}},
		{map[string]any{"op": "playback", "server": "10.0.0.9", "tcpPort": 1111, "udpPort": 1112, "channel": 1, "media": "video", "mode": "fastForward", "speed": 4, "start": start},
			0x9201, append(append(append(append([]byte(nil), srv...), 1, 2, 0, 0, 1, 3), startBCD...), 0, 0, 0, 0, 0, 0)},
		{map[string]any{"op": "playbackControl", "channel": 1, "control": "pause"}, 0x9202, []byte{1, 1, 0, 0, 0, 0, 0, 0, 0}},
		{map[string]any{"op": "listResources", "channel": 1, "start": start, "alarms": 4},
			0x9205, append(append(append([]byte{1}, startBCD...), 0, 0, 0, 0, 0, 0), 0, 0, 0, 0, 0, 0, 0, 4, 3, 0, 0)},
	} {
		f, err := commandFrame(t, "", false, c.content, 0x0102)
		if err != nil {
			t.Errorf("%v: %v", c.content, err)
			continue
		}
		if f.ID != c.id || !bytes.Equal(f.Body, c.body) {
			t.Errorf("%v: 0x%04X % X", c.content, f.ID, f.Body)
		}
	}
	for _, bad := range []map[string]any{
		{"op": "zoom"},
		{"op": "live", "tcpPort": 1},
		{"op": "live", "server": "x", "tcpPort": 1, "colour": 1},
		{"op": "liveControl", "channel": 1},
		{"op": "playback", "server": "x", "tcpPort": 1, "speed": 3, "start": start},
		{"op": "playback", "server": "x", "tcpPort": 1},
		{"op": "live", "server": "x", "tcpPort": 1, "data": "smell"},
		{"op": "rsaKey"},
		{"op": "attachmentUpload", "server": "x", "tcpPort": 1, "alarmLabel": "00"},
	} {
		if _, err := commandFrame(t, "", false, bad, 1); err == nil {
			t.Errorf("%v was framed", bad)
		}
	}

	// Answers on one connection that sent 0x9201 with serial 5.
	c := codec(t, "")
	decodeAll(t, c, vLocation)
	if _, _, err := c.Command("x", map[string]any{"op": "playback", "server": "x", "tcpPort": 1, "start": start}, 5); err != nil {
		t.Fatal(err)
	}
	attrs := []byte{0x13, 1, 0, 1, 0x01, 0x40, 1, 98, 4, 4}
	list := binary.BigEndian.AppendUint16(nil, 5)
	list = binary.BigEndian.AppendUint32(list, 1)
	list = append(append(append(list, 1), startBCD...), 0x26, 0x10, 0x11, 0x10, 0x45, 0x00)
	list = append(list, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1) // alarms, audio, main stream, main storage
	list = binary.BigEndian.AppendUint32(list, 1<<20)
	ms := decodeAll(t, c, frame(0x1003, 9, attrs), frame(0x1205, 10, list))
	cr := c.(track.Correlator)
	if want, _ := cr.Correlation(map[string]any{"op": "avAttributes"}, 99); ms[0].Correlation != want || ms[0].Details["maxVideoChannels"] != 4 || ms[0].Reply == nil {
		t.Fatalf("0x1003 %+v (want %s)", ms[0], want)
	}
	want, strict := cr.Correlation(map[string]any{"op": "playback", "server": "x", "tcpPort": 1, "start": start}, 5)
	res, _ := ms[1].Details["resources"].([]any)
	if ms[1].Correlation != want || !strict || len(res) != 1 {
		t.Fatalf("0x1205 %+v (want %s)", ms[1], want)
	}
	r0 := res[0].(map[string]any)
	if r0["start"] != "2026-10-11T02:30:00Z" || r0["media"] != "audio" || r0["size"] != uint32(1<<20) {
		t.Fatalf("resource %v", r0)
	}
}

func rsaKey(t *testing.T) (*rsa.PrivateKey, string) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	p := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
	return k, string(p)
}

// encrypted frames body with the RSA bit, encrypted for pub.
func encrypted(t *testing.T, pub *rsa.PublicKey, id, serial uint16, body []byte) string {
	t.Helper()
	enc, err := jt808.EncryptBody(pub, body)
	if err != nil {
		t.Fatal(err)
	}
	return hex.EncodeToString(jt808.EncodeWith(jt808.Header{ID: id, Version: -1, Phone: phone13, Serial: serial, Props: jt808.PropRSA}, enc))
}

// RSA key exchange and encrypted bodies: a terminal's 0x0A00 is answered
// with the platform key, its encrypted location (two blocks) is read,
// commands to it are encrypted for its key, a body that does not decrypt
// is answered as a message error, and the rsaKey command sends 0x8A00.
func TestRSABodies(t *testing.T) {
	plat, pemKey := rsaKey(t)
	term, _ := rsaKey(t)
	profile, _ := json.Marshal(map[string]any{"rsaPrivateKey": pemKey})
	c := codec(t, string(profile))
	loc := append(basic(), item(0xE1, bytes.Repeat([]byte{0xAB}, 100))...) // 130 bytes: two blocks
	ms := decodeAll(t, c, frame(0x0A00, 1, jt808.PublicKeyBody(&term.PublicKey)), encrypted(t, &plat.PublicKey, 0x0200, 2, loc),
		encrypted(t, &term.PublicKey, 0x0200, 3, loc))
	a := frameOf(t, ms[0].Reply)
	got, err := jt808.ParsePublicKeyBody(a.Body)
	if a.ID != jt808.MPlatformRSA || err != nil || !got.Equal(&plat.PublicKey) {
		t.Fatalf("0x8A00 answer %+v %v", a, err)
	}
	if len(ms[1].Records) != 1 || ms[1].Records[0].Fix.Lat != 12.97 || ms[1].Records[0].Status["item0xE1"] == nil {
		t.Fatalf("decrypted location %+v", ms[1])
	}
	if len(ms[2].Records) != 0 || frameOf(t, ms[2].Reply).Body[4] != jt808.ResultBadMessage || ms[2].Warnings[0].Code != "decryptFailed" {
		t.Fatalf("undecryptable %+v", ms[2])
	}
	b, _, err := c.Command("x", map[string]any{"action": "reboot"}, 4)
	if err != nil {
		t.Fatal(err)
	}
	f := frameOf(t, b)
	plain, err := jt808.DecryptBody(term, f.Body)
	if f.Props&jt808.PropRSA == 0 || err != nil || !bytes.Equal(plain, []byte{jt808.CtrlReset}) {
		t.Fatalf("encrypted command %+v %v", f.Header, err)
	}
	b, _, err = c.Command("x", map[string]any{"op": "rsaKey"}, 5)
	if f = frameOf(t, b); err != nil || f.ID != jt808.MPlatformRSA || f.Props&jt808.PropRSA != 0 {
		t.Fatalf("rsaKey %+v %v", f, err)
	}
	if want, _ := c.(track.Correlator).Correlation(map[string]any{"op": "rsaKey"}, 5); ms[0].Correlation != want {
		t.Fatalf("0x0A00 correlation %q, want %q", ms[0].Correlation, want)
	}
	// encryptCommands false sends commands in the clear.
	profile, _ = json.Marshal(map[string]any{"rsaPrivateKey": pemKey, "encryptCommands": false})
	c = codec(t, string(profile))
	decodeAll(t, c, frame(0x0A00, 1, jt808.PublicKeyBody(&term.PublicKey)))
	b, _, _ = c.Command("x", map[string]any{"action": "reboot"}, 4)
	if f := frameOf(t, b); f.Props&jt808.PropRSA != 0 || !bytes.Equal(f.Body, []byte{jt808.CtrlReset}) {
		t.Fatalf("clear command %+v", f)
	}
	if _, err := jt808.NewCodec(json.RawMessage(`{"rsaPrivateKey": "not a key"}`)); err == nil {
		t.Fatal("a bad key was accepted")
	}
}

// A subpackaged batch is answered piece by piece and read when whole.
func TestSubpackages(t *testing.T) {
	body := binary.BigEndian.AppendUint16(nil, 3)
	body = append(body, 1)
	for range 3 {
		l := basic()
		body = append(binary.BigEndian.AppendUint16(body, uint16(len(l))), l...)
	}
	h := jt808.Header{ID: jt808.MBatch, Version: -1, Phone: phone13, Total: 2}
	h.Index, h.Serial = 1, 10
	p1 := hex.EncodeToString(jt808.EncodeWith(h, body[:50]))
	h.Index, h.Serial = 2, 11
	p2 := hex.EncodeToString(jt808.EncodeWith(h, body[50:]))
	ms := decodeAll(t, codec(t, ""), p1, p2)
	if len(ms) != 2 || len(ms[0].Records) != 0 || len(ms[1].Records) != 3 || !ms[1].Records[0].History {
		t.Fatalf("subpackages %+v", ms)
	}
	if a := frameOf(t, ms[0].Reply); !bytes.Equal(a.Body, []byte{0, 10, 0x07, 0x04, 0}) {
		t.Fatalf("piece answer % X", a.Body)
	}
	if !ms[1].Records[0].Fix.Time.Equal(time.Date(2026, 10, 11, 4, 0, 0, 0, time.UTC)) {
		t.Fatalf("time %v", ms[1].Records[0].Fix.Time)
	}
}
