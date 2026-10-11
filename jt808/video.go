// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package jt808

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/cB-Sigma/trackers/track"
)

// JT/T 1078 video signalling, the messages a JT808 connection carries
// (the media streams go to the media server the commands name and are
// not read here): 0x9003 audio/video attribute query (answered 0x1003),
// 0x9101 live request, 0x9102 live control, 0x9201 playback request,
// 0x9202 playback control, 0x9205 resource list query (answered 0x1205
// with the query's serial; some terminals answer 0x9201 with 0x1205 too,
// others with 0x0001). Layouts as JT/T 1078-2016 describes them, checked
// against the public go-jt808 documentation.

// JT/T 1078 message IDs.
const (
	MAVAttributes      = 0x1003
	MResourceList      = 0x1205
	MAVAttributesQuery = 0x9003
	MLiveRequest       = 0x9101
	MLiveControl       = 0x9102
	MPlaybackRequest   = 0x9201
	MPlaybackControl   = 0x9202
	MResourceQuery     = 0x9205
)

// args reads the members of an own-form command ({"op": ...}).
type args struct {
	op   string
	m    map[string]any
	used map[string]bool
	err  error
	loc  *time.Location
}

func (a *args) fail(err error) {
	if a.err == nil {
		a.err = err
	}
}

func (a *args) get(k string) (any, bool) {
	a.used[k] = true
	v, ok := a.m[k]
	return v, ok
}

func (a *args) str(k string) string {
	v, ok := a.get(k)
	if !ok {
		return ""
	}
	s, isStr := v.(string)
	if !isStr {
		a.fail(fmt.Errorf("%s: %q is text", a.op, k))
	}
	return s
}

// num reads a whole number in [lo, hi]; def when absent.
func (a *args) num(k string, lo, hi, def int) int {
	v, ok := a.get(k)
	if !ok {
		return def
	}
	var n int
	switch x := v.(type) {
	case float64:
		n = int(x)
		if float64(n) != x {
			a.fail(fmt.Errorf("%s: %q is a whole number", a.op, k))
		}
	case int:
		n = x
	default:
		a.fail(fmt.Errorf("%s: %q is a number", a.op, k))
	}
	if n < lo || n > hi {
		a.fail(fmt.Errorf("%s: %q is %d to %d", a.op, k, lo, hi))
	}
	return n
}

// enum reads one of names (by name, or its index as a number).
func (a *args) enum(k string, names []string, def int) int {
	v, ok := a.get(k)
	if !ok {
		return def
	}
	if s, isStr := v.(string); isStr {
		for i, n := range names {
			if n != "" && strings.EqualFold(n, s) {
				return i
			}
		}
		var list []string
		for _, n := range names {
			if n != "" {
				list = append(list, n)
			}
		}
		a.fail(fmt.Errorf("%s: %q is one of %s", a.op, k, strings.Join(list, ", ")))
		return def
	}
	delete(a.used, k)
	return a.num(k, 0, len(names)-1, def)
}

// when reads an RFC 3339 time; zero when absent.
func (a *args) when(k string) time.Time {
	s := a.str(k)
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		a.fail(fmt.Errorf("%s: %q is an RFC 3339 time", a.op, k))
	}
	return t
}

// server reads the media or attachment server: "server", "tcpPort",
// "udpPort" (one port at least).
func (a *args) server() (string, int, int, error) {
	s := a.str("server")
	tcp, udp := a.num("tcpPort", 0, 65535, 0), a.num("udpPort", 0, 65535, 0)
	if a.err != nil {
		return "", 0, 0, a.err
	}
	if s == "" || len(s) > 255 || tcp == 0 && udp == 0 {
		return "", 0, 0, fmt.Errorf(`%s needs "server" (host name or address) and "tcpPort" or "udpPort"`, a.op)
	}
	return s, tcp, udp, nil
}

// done refuses members the command does not take.
func (a *args) done() error {
	if a.err != nil {
		return a.err
	}
	var extra []string
	for k := range a.m {
		if !a.used[k] && k != "op" {
			extra = append(extra, k)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return fmt.Errorf("%s takes no member %s", a.op, strings.Join(extra, ", "))
	}
	return nil
}

var (
	liveData     = []string{"av", "video", "talk", "listen", "broadcast", "passThrough"}
	streams01    = []string{"main", "sub"}
	liveCtrl     = []string{"close", "switchStream", "pause", "resume", "closeTalk"}
	closeKinds   = []string{"all", "audio", "video"}
	mediaKinds   = []string{"av", "audio", "video", "any"}
	streams012   = []string{"any", "main", "sub"}
	storages     = []string{"any", "main", "backup"}
	playModes    = []string{"normal", "fastForward", "rewind", "keyFrames", "singleFrame"}
	playCtrl     = []string{"start", "pause", "stop", "fastForward", "rewind", "seek", "keyFrames"}
	speedFactors = []int{0, 1, 2, 4, 8, 16}
)

// Ops are the own-form commands ({"op": ...}).
var Ops = []string{"avAttributes", "live", "liveControl", "playback", "playbackControl", "listResources", "attachmentUpload", "rsaKey"}

// speed reads "speed" (1, 2, 4, 8 or 16 times) as its code.
func (a *args) speed() int {
	v := a.num("speed", 0, 16, 0)
	for i, s := range speedFactors {
		if s == v {
			return i
		}
	}
	a.fail(fmt.Errorf(`%s: "speed" is 1, 2, 4, 8 or 16`, a.op))
	return 0
}

func serverBytes(srv string, tcp, udp int) []byte {
	b := append([]byte{byte(len(srv))}, srv...)
	b = binary.BigEndian.AppendUint16(b, uint16(tcp))
	return binary.BigEndian.AppendUint16(b, uint16(udp))
}

// planOp frames an own-form command.
func (c *codec) planOp(m map[string]any) (*planned, error) {
	op, _ := m["op"].(string)
	a := args{op: op, m: m, used: map[string]bool{}, loc: c.cfg.loc}
	switch op {
	case "avAttributes":
		if err := a.done(); err != nil {
			return nil, err
		}
		return &planned{id: MAVAttributesQuery}, nil
	case "live":
		srv, tcp, udp, err := a.server()
		if err != nil {
			return nil, err
		}
		b := serverBytes(srv, tcp, udp)
		b = append(b, byte(a.num("channel", 1, 255, 1)), byte(a.enum("data", liveData, 0)), byte(a.enum("stream", streams01, 0)))
		if err := a.done(); err != nil {
			return nil, err
		}
		return &planned{id: MLiveRequest, body: b}, nil
	case "liveControl":
		b := []byte{byte(a.num("channel", 1, 255, 1)), byte(a.enum("control", liveCtrl, 0)), byte(a.enum("close", closeKinds, 0)), byte(a.enum("stream", streams01, 0))}
		if _, ok := m["control"]; !ok {
			return nil, errors.New(`liveControl needs "control": close, switchStream, pause, resume or closeTalk`)
		}
		if err := a.done(); err != nil {
			return nil, err
		}
		return &planned{id: MLiveControl, body: b}, nil
	case "playback":
		srv, tcp, udp, err := a.server()
		if err != nil {
			return nil, err
		}
		b := serverBytes(srv, tcp, udp)
		b = append(b, byte(a.num("channel", 1, 255, 1)), byte(a.enum("media", mediaKinds, 0)), byte(a.enum("stream", streams012, 0)),
			byte(a.enum("storage", storages, 0)), byte(a.enum("mode", playModes, 0)), byte(a.speed()))
		start, end := a.when("start"), a.when("end")
		if err := a.done(); err != nil {
			return nil, err
		}
		if start.IsZero() {
			return nil, errors.New(`playback needs "start", an RFC 3339 time ("end" absent plays to the end)`)
		}
		b = append(append(b, BCDTime(start, c.cfg.loc)...), BCDTime(end, c.cfg.loc)...)
		return &planned{id: MPlaybackRequest, body: b}, nil
	case "playbackControl":
		if _, ok := m["control"]; !ok {
			return nil, errors.New(`playbackControl needs "control": start, pause, stop, fastForward, rewind, seek or keyFrames`)
		}
		b := []byte{byte(a.num("channel", 1, 255, 1)), byte(a.enum("control", playCtrl, 0)), byte(a.speed())}
		at := a.when("at")
		if err := a.done(); err != nil {
			return nil, err
		}
		return &planned{id: MPlaybackControl, body: append(b, BCDTime(at, c.cfg.loc)...)}, nil
	case "listResources":
		b := []byte{byte(a.num("channel", 0, 255, 0))}
		b = append(b, BCDTime(a.when("start"), c.cfg.loc)...)
		b = append(b, BCDTime(a.when("end"), c.cfg.loc)...)
		alarms := uint64(0)
		if v, ok := a.get("alarms"); ok {
			f, isNum := v.(float64)
			if i, isInt := v.(int); isInt {
				f, isNum = float64(i), true
			}
			if !isNum || f < 0 || f >= 1<<64 || f != float64(uint64(f)) {
				a.fail(errors.New(`listResources: "alarms" is the 64-bit alarm flag mask, a whole number`))
			}
			alarms = uint64(f)
		}
		b = binary.BigEndian.AppendUint64(b, alarms)
		b = append(b, byte(a.enum("media", mediaKinds, 3)), byte(a.enum("stream", streams012, 0)), byte(a.enum("storage", storages, 0)))
		if err := a.done(); err != nil {
			return nil, err
		}
		return &planned{id: MResourceQuery, body: b}, nil
	case "attachmentUpload":
		return planAttachmentUpload(a)
	case "rsaKey":
		if err := a.done(); err != nil {
			return nil, err
		}
		if c.cfg.key == nil {
			return nil, errors.New("rsaKey sends the platform's RSA public key: set profile.rsaPrivateKey first")
		}
		return &planned{id: MPlatformRSA, body: PublicKeyBody(&c.cfg.key.PublicKey), plain: true}, nil
	}
	return nil, fmt.Errorf("op %q is not one of %s", op, strings.Join(Ops, ", "))
}

// Resource is one recording of a 0x1205 resource list.
type Resource struct {
	Channel    int
	Start, End time.Time
	Alarms     uint64
	Media      string // av, audio or video
	Stream     string // main or sub
	Storage    string // main or backup
	Size       uint32
}

// parseResources reads a 0x1205 body: the query's serial, the count, the
// 28-byte items.
func parseResources(b []byte, loc *time.Location) (uint16, []Resource, error) {
	if len(b) < 6 {
		return 0, nil, errors.New("a resource list under 6 bytes")
	}
	serial, n := binary.BigEndian.Uint16(b), int(binary.BigEndian.Uint32(b[2:]))
	rest := b[6:]
	if len(rest) < 28*n {
		return serial, nil, fmt.Errorf("a resource list of %d items is cut short", n)
	}
	out := make([]Resource, 0, n)
	for i := 0; i < n; i++ {
		x := rest[28*i : 28*i+28]
		r := Resource{Channel: int(x[0]), Alarms: binary.BigEndian.Uint64(x[13:]), Size: binary.BigEndian.Uint32(x[24:])}
		r.Start, _ = bcdTime(x[1:7], loc)
		r.End, _ = bcdTime(x[7:13], loc)
		r.Media = pick(mediaKinds, x[21])
		r.Stream = pick(streams012, x[22])
		r.Storage = pick(storages, x[23])
		out = append(out, r)
	}
	return serial, out, nil
}

func pick(names []string, v byte) string {
	if int(v) < len(names) {
		return names[v]
	}
	return fmt.Sprintf("%d", v)
}

var audioRates = []string{"8kHz", "22.05kHz", "44.1kHz", "48kHz"}
var audioBits = []string{"8", "16", "32"}

// videoMessage reads 0x1003 and 0x1205.
func (c *codec) videoMessage(f *Frame, m *track.Message) {
	m.Kind = "response"
	m.Reply = c.general(f, ResultOK)
	b := f.Body
	switch f.ID {
	case MAVAttributes:
		if len(b) < 10 {
			m.Warnings = append(m.Warnings, short(f, errors.New("audio/video attributes under 10 bytes")))
			return
		}
		m.Correlation = correlation(MAVAttributesQuery, 0)
		m.Details = map[string]any{"audioCoding": int(b[0]), "audioChannels": int(b[1]), "audioRate": pick(audioRates, b[2]),
			"audioBits": pick(audioBits, b[3]), "audioFrame": int(binary.BigEndian.Uint16(b[4:])), "audioOutput": b[6] == 1,
			"videoCoding": int(b[7]), "maxAudioChannels": int(b[8]), "maxVideoChannels": int(b[9])}
		text := fmt.Sprintf("%d video and %d audio channels", b[9], b[8])
		m.Response = &text
		m.Records = []track.Record{{Status: map[string]any{"videoChannels": int(b[9]), "audioChannels": int(b[8])}}}
	case MResourceList:
		serial, rs, err := parseResources(b, c.cfg.loc)
		if len(b) >= 2 {
			m.Correlation = correlation(c.listedBy(serial), serial)
		}
		if err != nil {
			m.Warnings = append(m.Warnings, short(f, err))
			text := "resource list cut short"
			m.Response, m.Failed = &text, true
			return
		}
		list := make([]any, len(rs))
		for i, r := range rs {
			x := map[string]any{"channel": r.Channel, "alarms": r.Alarms, "media": r.Media, "stream": r.Stream, "storage": r.Storage, "size": r.Size}
			if !r.Start.IsZero() {
				x["start"] = r.Start.Format(time.RFC3339)
			}
			if !r.End.IsZero() {
				x["end"] = r.End.Format(time.RFC3339)
			}
			list[i] = x
		}
		m.Details = map[string]any{"resources": list}
		text := fmt.Sprintf("%d recordings", len(rs))
		m.Response = &text
	}
}

// listed notes the message ID of a 0x9201 or 0x9205 sent with serial, so
// that the 0x1205 answering it (which names only the serial) names it.
func (c *codec) listed(serial, id uint16) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lists == nil || len(c.lists) > 256 {
		c.lists = map[uint16]uint16{}
	}
	c.lists[serial] = id
}

func (c *codec) listedBy(serial uint16) uint16 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if id, ok := c.lists[serial]; ok {
		return id
	}
	return MResourceQuery
}
