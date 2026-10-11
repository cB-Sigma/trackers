package jt808_test

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/trackers/jt808"
	"github.com/cB-Sigma/trackers/track"
)

func h(s string) []byte {
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		panic(err)
	}
	return b
}

// Frames from real JT808 terminals as quoted in Traccar's open test suite
// (Apache-2.0, Jt808ProtocolDecoderTest; see NOTICE): facts used as test
// vectors. Their check codes all match.
const (
	vRegister2013 = "7E0100002D013511221122000500000000373031303748422D52303347424400000000000000000000003233363631303402CBD5424136383630387E"
	vAuth2013     = "7E0102000E013511221122000661757468656E7469636174696F6E3F7E"
	vLocation     = "7e0200002c00160128561400020000000000040001005de1f7065c6cef00000000000017011710044201040000a9002a02000030011b3101030c7e"
	vLocateAnswer = "7e0201003c0145382363912db0000000000000000000020101313605bb3b58000c000001292608251203040104000b620beb16000c00b28995018202107439115800060089fffffffece7e"
	vBatch2019    = "7e0704402d0100000866496077582164881d0001000028000000000000000701a00192091f2a4700160000000226050916422701040000258230010031010e507e"
	vBlind2013    = "7e070400510144503762020002000101004c00040100000800030202301006f893e8001d00000095260817221812140400000000170200000104000036c9030200002504000000002a02000030011f31010eea04020c8300ef0400000000037e"
	vText6006     = "7e60060055014164192753005a003c5645523a53444b3a42433738455f5045545f56312e30325f3234303631312c4150503a50455431302348573031344a54533130323033443234313130345f4e6f7620203420323032345f31343a34393a33343e4c7e"
	vRegister2019 = "7e0100405c010000086649607758216452180000000000000000000000000000004d443330300000000000000000000000000000000000000000000000000038363634393630373735383231363400000000000000000000000000000004000000000000000000000000000000007a7e"
)

func codec(t *testing.T, profile string) track.Codec {
	t.Helper()
	nc, err := jt808.NewCodec(json.RawMessage(profile))
	if err != nil {
		t.Fatal(err)
	}
	return nc()
}

// decodeAll decodes frames on one connection; a skipped frame is nil.
func decodeAll(t *testing.T, c track.Codec, frames ...string) []*track.Message {
	t.Helper()
	var buf bytes.Buffer
	for _, f := range frames {
		buf.Write(h(f))
	}
	br := bufio.NewReader(&buf)
	var out []*track.Message
	for {
		m, err := c.Decode(br)
		if errors.Is(err, track.ErrSkip) {
			out = append(out, nil)
			continue
		}
		if err != nil {
			return out
		}
		out = append(out, m)
	}
}

func frameOf(t *testing.T, b []byte) *jt808.Frame {
	t.Helper()
	f, err := jt808.ReadFrame(bufio.NewReader(bytes.NewReader(b)))
	if err != nil {
		t.Fatal(err)
	}
	if !f.CheckOK {
		t.Fatalf("check code of % X", b)
	}
	return f
}

// The escape example of JT/T 808-2013 4.4.2 and the published frames:
// registration and its answer with an authentication code, authentication,
// location (GMT+8 time to UTC, 1/10 km/h, items), location query answer,
// batches in both header forms (type 1 to history, with the alarm flags
// as alerts), and a Jimi 0x6006 text answer.
//
// Covers: SIG-IMP-033
func TestPublishedFrames(t *testing.T) {
	if got := jt808.Escape(h("307e087d55")); !bytes.Equal(got, h("307d02087d0155")) {
		t.Fatalf("escape % X", got)
	}
	if got := jt808.Unescape(h("307d02087d0155")); !bytes.Equal(got, h("307e087d55")) {
		t.Fatalf("unescape % X", got)
	}
	c := codec(t, "")
	ms := decodeAll(t, c, vRegister2013, vAuth2013)
	if len(ms) != 2 || ms[0] == nil || ms[1] == nil {
		t.Fatalf("decoded %v", ms)
	}
	reg := ms[0]
	if reg.IMEI != "013511221122" || !reg.Login || reg.Records[0].Status["model"] != "HB-R03GBD" || reg.Records[0].Status["terminalId"] != "2366104" {
		t.Fatalf("registration %+v", reg)
	}
	ans := frameOf(t, reg.Reply)
	if ans.ID != jt808.MRegisterAnswer || ans.PhoneDigits() != "013511221122" || ans.V2019() || !bytes.Equal(ans.Body[:3], []byte{0x00, 0x05, 0x00}) || len(ans.Body) < 4 {
		t.Fatalf("0x8100 %+v", ans)
	}
	if rej := frameOf(t, reg.Reject); rej.Body[2] != 4 {
		t.Fatalf("refusal result %d", rej.Body[2])
	}
	if a := frameOf(t, ms[1].Reply); a.ID != jt808.MPlatformResponse || !bytes.Equal(a.Body, []byte{0x00, 0x06, 0x01, 0x02, 0x00}) || !ms[1].Login {
		t.Fatalf("auth answer % X", a.Body)
	}

	ms = decodeAll(t, codec(t, ""), vLocation, vLocateAnswer, vBatch2019, vBlind2013, vText6006, vRegister2019)
	if len(ms) != 6 {
		t.Fatalf("decoded %d frames", len(ms))
	}
	loc := ms[0].Records[0]
	f := loc.Fix
	if f.Time != time.Date(2017, 1, 17, 2, 4, 42, 0, time.UTC) || f.Lat != 6.152695 || f.Lon != 106.720495 || *f.Speed != 0 || *f.Sats != 3 {
		t.Fatalf("location %+v", f)
	}
	if loc.Status["ignition"] != true || loc.Status["odometer"] != 4326.4 || loc.Status["gsm"] != 27 || len(loc.Alerts) != 0 {
		t.Fatalf("location status %v", loc.Status)
	}
	if a := frameOf(t, ms[0].Reply); a.ID != jt808.MPlatformResponse || !bytes.Equal(a.Body, []byte{0x00, 0x02, 0x02, 0x00, 0x00}) {
		t.Fatalf("location answer % X", a.Body)
	}
	q := ms[1]
	if q.Records[0].Fix.Time != time.Date(2026, 8, 25, 4, 3, 4, 0, time.UTC) || q.Records[0].Fix.Lat != 16.85535 || q.Records[0].Fix.Lon != 96.156504 ||
		q.Response == nil || q.Correlation != "8201#0" || q.Reply != nil {
		t.Fatalf("0x0201 %+v", q)
	}
	b19 := ms[2]
	if b19.IMEI != "00000866496077582164" || len(b19.Records) != 1 || b19.Records[0].History || b19.Records[0].Fix.Lat >= 0 {
		t.Fatalf("2019 batch %+v", b19)
	}
	if a := frameOf(t, b19.Reply); !a.V2019() || a.Version != 1 || a.PhoneDigits() != "00000866496077582164" {
		t.Fatalf("2019 answer header %+v", a.Header)
	}
	blind := ms[3].Records[0]
	if !blind.History || len(blind.Alerts) != 2 || blind.Alerts[0].Type != "main-power-removed" || blind.Alerts[0].Code != "bit8" {
		t.Fatalf("blind batch %+v", blind)
	}
	if r := ms[4]; r.Response == nil || !strings.HasPrefix(*r.Response, "<VER:SDK:BC78E_PET") || r.Failed || r.Reply == nil {
		t.Fatalf("0x6006 %+v", r)
	}
	if r := ms[5]; !r.Login || r.IMEI != "00000866496077582164" || r.Records[0].Status["terminalId"] != "866496077582164" {
		t.Fatalf("2019 registration %+v", r)
	}
}

// A frame whose check code does not match is skipped with crcMismatch and
// the next frame is read; checkCrc false takes it. Noise before a flag is
// passed over, and frames sharing one flag are both read.
//
// Covers: SIG-IMP-033
func TestCheckCodeAndResync(t *testing.T) {
	bad := strings.Replace(vLocation, "030c7e", "03ff7e", 1)
	ms := decodeAll(t, codec(t, ""), bad, vAuth2013)
	if len(ms) != 2 || ms[0] != nil || ms[1] == nil {
		t.Fatalf("strict %v", ms)
	}
	var sk *track.Skip
	_, err := codec(t, "").Decode(bufio.NewReader(bytes.NewReader(h(bad))))
	if !errors.As(err, &sk) || sk.Code != "crcMismatch" || sk.Setting != "profile.checkCrc" {
		t.Fatalf("skip %v", err)
	}
	if ms := decodeAll(t, codec(t, `{"checkCrc": false}`), bad); len(ms) != 1 || ms[0] == nil {
		t.Fatal("checkCrc false refused the frame")
	}
	shared := "0102" + vLocation + strings.TrimPrefix(strings.ToLower(vAuth2013), "7e")
	if ms := decodeAll(t, codec(t, ""), shared); len(ms) != 2 || ms[0] == nil || ms[1] == nil || !ms[1].Login {
		t.Fatalf("noise and shared flag %v", ms)
	}
}

// An unknown message is acknowledged and passed over with a warning; an
// encrypted one is answered "not supported"; the connection reads on.
//
// Covers: SIG-IMP-033
func TestUnknownMessagesPassedOver(t *testing.T) {
	phone := jt808.PhoneBCD("013511221122", 6)
	attrs := jt808.Encode(jt808.Header{ID: 0x0107, Version: -1, Phone: phone, Serial: 9}, []byte{1, 2, 3})
	ms := decodeAll(t, codec(t, ""), hex.EncodeToString(attrs), vLocation)
	if len(ms) != 2 || ms[0] == nil || len(ms[0].Warnings) != 1 || ms[0].Warnings[0].Code != "unknownMessage" || ms[1] == nil || len(ms[1].Records) != 1 {
		t.Fatalf("unknown %+v", ms)
	}
	if a := frameOf(t, ms[0].Reply); !bytes.Equal(a.Body, []byte{0x00, 0x09, 0x01, 0x07, 0x00}) {
		t.Fatalf("ack % X", a.Body)
	}
	enc := h(hex.EncodeToString(jt808.Encode(jt808.Header{ID: 0x0200, Version: -1, Phone: phone, Serial: 3}, make([]byte, 28))))
	// Set the RSA bit (10) in the attributes and redo the check code.
	raw := jt808.Unescape(enc[1 : len(enc)-1])
	raw[2] |= 0x04
	raw[len(raw)-1] = jt808.Check(raw[:len(raw)-1])
	frame := append(append([]byte{0x7E}, jt808.Escape(raw)...), 0x7E)
	ms = decodeAll(t, codec(t, ""), hex.EncodeToString(frame))
	if len(ms) != 1 || ms[0] == nil || len(ms[0].Records) != 0 || frameOf(t, ms[0].Reply).Body[4] != jt808.ResultUnsupported {
		t.Fatalf("encrypted %+v", ms)
	}
}

// The timezone profile setting moves the device clock; ±hh:mm and IANA
// names are read, other values refused.
//
// Covers: SIG-IMP-037
func TestTimezoneOption(t *testing.T) {
	ms := decodeAll(t, codec(t, `{"timezone": "+05:30"}`), vLocation)
	if got := ms[0].Records[0].Fix.Time; got != time.Date(2017, 1, 17, 4, 34, 42, 0, time.UTC) {
		t.Fatalf("+05:30: %v", got)
	}
	ms = decodeAll(t, codec(t, `{"timezone": "UTC"}`), vLocation)
	if got := ms[0].Records[0].Fix.Time; got != time.Date(2017, 1, 17, 10, 4, 42, 0, time.UTC) {
		t.Fatalf("UTC: %v", got)
	}
	for _, p := range []string{`{"timezone": "Mars/Base"}`, `{"engineControl": "relay"}`, `{"textCommand": "8301"}`, `{"textFlag": 300}`,
		`{"namedCommands": {"reboot": "RESET {password}"}}`, `{"failureWords": [""]}`, `{"unknown": 1}`} {
		if _, err := jt808.NewCodec(json.RawMessage(p)); err == nil {
			t.Errorf("%s was accepted", p)
		}
	}
}
