// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package ruptela

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/cB-Sigma/trackers/track"
)

// More device command IDs (Ruptela Protocol v1.113).
const (
	CmdConfig       = 2  // configuration answer (ASCII)
	CmdVersion      = 3  // version answer (ASCII)
	CmdFirmware     = 4  // firmware update answer (ASCII)
	CmdCardData     = 5  // tachograph smart card file data
	CmdCardInfo     = 6  // smart card file size and time
	CmdTacho        = 10 // tachograph communication
	CmdTachoData    = 11 // tachograph data packet
	CmdTachoInfo    = 12 // tachograph information packet
	CmdTransparent  = 14 // transparent channel (serial port data)
	CmdCard2Info    = 19 // second-generation smart card size and time
	CmdGarminStatus = 30 // Garmin status answer
	CmdGarminData   = 31 // Garmin FMI data
	CmdWeighing     = 32 // weighing system data
	CmdFLS          = 33 // fuel level sensor channel
	CmdSDLog        = 34 // SD card logging
	CmdAccident     = 35 // accident reconstruction data
	CmdFiles        = 37 // files (camera pictures)
	CmdBeacons      = 38 // beacon data
)

// More server command IDs.
const (
	Config         = 102
	GetVersion     = 103
	Firmware       = 104
	SetConnection  = 105
	SetOdometer    = 106
	AckCard        = 107
	Tacho          = 110
	AckTacho       = 111
	AckTransparent = 114
	GarminStatus   = 130
	Garmin         = 131
	AckWeighing    = 132
	FLS            = 133
	SDLog          = 134
	AckAccident    = 135
	Files          = 137
	AckBeacons     = 138
)

// MaxPicture bounds a file reassembled from command 37 packets.
const MaxPicture = 4 << 20

// Picture is a camera file a device sent with command 37 (subcommand 2).
type Picture struct {
	Name   string // the 8-character file name
	Source int    // 0, 1 camera A or B SD card; 2, 3 camera memory on port A or B; 4, 5 fatigue camera
	Data   []byte
}

// PictureOf returns the file a decoded message carries: the message of a
// file's last packet holds the whole file.
func PictureOf(m *track.Message) (*Picture, bool) {
	if m == nil {
		return nil, false
	}
	p, ok := m.Details["picture"].(*Picture)
	return p, ok
}

type assembly struct {
	name   string
	source int
	total  int
	parts  map[int][]byte
	size   int
}

var ports = []string{"A", "B", "C"}

func portName(b byte) string {
	if int(b) < len(ports) {
		return ports[b]
	}
	return strconv.Itoa(int(b))
}

// more decodes the commands beyond records, identification, heartbeat,
// SMS and set-IO answers. It returns a Skip for packets passed over.
func (c *codec) more(cmd byte, p []byte, m *track.Message) error {
	switch cmd {
	case CmdConfig, CmdFirmware:
		text := strings.TrimSpace(string(p))
		m.Kind, m.Response = "response", &text
		m.Failed = track.AnswerFailed(text, c.cfg.fail)
	case CmdVersion:
		text := strings.TrimSpace(string(p))
		m.Kind, m.Response = "response", &text
		f := strings.Split(text, ",")
		if len(f) == 5 {
			m.Details = map[string]any{"bootloader": f[0], "firmware": f[1], "hardware": f[2]}
			if v, err := strconv.Atoi(f[3]); err == nil {
				m.Details["gsm"] = v
			}
			m.Details["voltageOk"] = f[4] == "1"
		}
	case CmdDTC:
		m.Kind = "health"
		m.Reply = ack(AckDTC, 1)
		recs, ok := dtcs(p)
		if !ok {
			m.Records = []track.Record{{Status: map[string]any{"dtc": fmt.Sprintf("%X", p)}, Time: time.Now()}}
			m.Warnings = append(m.Warnings, track.Warning{Code: "fieldUnreadable", Detail: fmt.Sprintf("% X", clip(p)),
				Msg: "A DTC packet whose entries could not be read was kept as hexadecimal."})
			break
		}
		m.Records = recs
	case CmdTransparent:
		if len(p) < 8 {
			return short("transparent channel")
		}
		t := time.Unix(int64(binary.BigEndian.Uint32(p[3:7])), 0).UTC()
		m.Kind = "normal"
		m.Records = []track.Record{{Time: t, Status: map[string]any{"port": portName(p[0]), "serialData": fmt.Sprintf("%X", p[7:])}}}
		m.Reply = ServerFrame(AckTransparent, []byte{p[0], 0, 0})
	case CmdWeighing:
		if len(p) < 14 {
			return short("weighing")
		}
		t := time.Unix(int64(binary.BigEndian.Uint32(p[0:4])), 0).UTC()
		lon := float64(int32(binary.BigEndian.Uint32(p[4:8]))) / 1e7
		lat := float64(int32(binary.BigEndian.Uint32(p[8:12]))) / 1e7
		m.Kind = "normal"
		m.Records = []track.Record{{Time: t, Fix: &track.Fix{Time: t, Lat: lat, Lon: lon, Valid: p[12] == 1},
			Status: map[string]any{"port": portName(p[13]), "weighing": strings.TrimSpace(string(p[14:]))}}}
		m.Reply = ack(AckWeighing, 1)
	case CmdGarminStatus:
		if len(p) < 1 {
			return short("Garmin status")
		}
		text := map[byte]string{1: "Garmin device not responding", 2: "Garmin device responding", 3: "Garmin device responding, with Unicode"}[p[0]]
		if text == "" {
			text = fmt.Sprintf("Garmin status %d", p[0])
		}
		m.Kind, m.Response, m.Failed = "response", &text, p[0] == 1
		m.Details = map[string]any{"garminStatus": int(p[0])}
	case CmdSDLog:
		return c.sdLog(p, m)
	case CmdFiles:
		return c.files(p, m)
	case CmdBeacons, CmdAccident:
		a := ack(AckBeacons, 1)
		what := "beacon data (38)"
		if cmd == CmdAccident {
			a, what = ack(AckAccident, 1), "accident reconstruction data (35)"
		}
		return &track.Skip{Reply: a, Warning: track.Warning{Code: "unknownMessage", Detail: fmt.Sprintf("command %d", cmd),
			Msg: "Ruptela " + what + " was acknowledged and passed over; this codec does not read it."}}
	default:
		return &track.Skip{Warning: track.Warning{Code: "unknownMessage", Detail: fmt.Sprintf("command %d", cmd),
			Msg: "A Ruptela packet of a command this codec does not read was passed over (the connection stays up)."}}
	}
	return nil
}

func short(what string) error {
	return &track.Skip{Warning: track.Warning{Code: "shortPacket", Detail: what,
		Msg: "A Ruptela " + what + " packet shorter than its fields was passed over."}}
}

func clip(b []byte) []byte {
	if len(b) > 32 {
		return b[:32]
	}
	return b
}

var dtcSources = map[byte]string{0xFF: "obd", 1: "j1939", 2: "j1708"}

// dtcs reads a DTC packet: a count, then per code its source, time,
// longitude, latitude, status (1 current, 2 history) and 5-byte code
// (text for OBD, bytes for J1939 and J1708).
func dtcs(p []byte) ([]track.Record, bool) {
	if len(p) < 1 || len(p) != 1+int(p[0])*19 || p[0] == 0 {
		return nil, false
	}
	var out []track.Record
	for i := 0; i < int(p[0]); i++ {
		e := p[1+i*19 : 1+(i+1)*19]
		t := time.Unix(int64(binary.BigEndian.Uint32(e[1:5])), 0).UTC()
		lon := float64(int32(binary.BigEndian.Uint32(e[5:9]))) / 1e7
		lat := float64(int32(binary.BigEndian.Uint32(e[9:13]))) / 1e7
		src, ok := dtcSources[e[0]]
		if !ok {
			src = strconv.Itoa(int(e[0]))
		}
		code := fmt.Sprintf("%X", e[14:19])
		if e[0] == 0xFF {
			code = strings.TrimRight(string(e[14:19]), "\x00 ")
		}
		rec := track.Record{Time: t, History: e[13] == 2,
			Status: map[string]any{"dtc": code, "dtcSource": src}}
		if lat != 0 || lon != 0 {
			rec.Fix = &track.Fix{Time: t, Lat: lat, Lon: lon, Valid: true}
		}
		out = append(out, rec)
	}
	return out, true
}

// sdLog reads SD card logging (34): records (subcommand 0x40 standard,
// 0x80 extended) or the answers to erase (0x10) and enable (0x20).
func (c *codec) sdLog(p []byte, m *track.Message) error {
	if len(p) < 2 {
		return short("SD card log")
	}
	switch p[0] {
	case 0x40, 0x80:
		recs, err := c.records(p[1:], p[0] == 0x80)
		if err != nil {
			return &track.Skip{Warning: track.Warning{Code: "unknownPacket", Detail: err.Error(),
				Msg: "SD card log records that could not be read were passed over."}}
		}
		for i := range recs {
			recs[i].History = true
		}
		m.Kind, m.Records, m.Reply = "normal", recs, ServerFrame(SDLog, []byte{1})
	case 0x10:
		text := map[bool]string{true: "SD card log erased", false: "SD card log not erased"}[p[1] == 1]
		m.Kind, m.Response, m.Failed = "response", &text, p[1] != 1
	case 0x20:
		text := map[byte]string{0: "SD card logging stopped", 1: "SD card logging started", 2: "SD card logging cannot start"}[p[1]]
		if text == "" {
			text = fmt.Sprintf("SD card logging status %d", p[1])
		}
		m.Kind, m.Response, m.Failed = "response", &text, p[1] > 1
	default:
		return &track.Skip{Warning: track.Warning{Code: "unknownMessage", Detail: fmt.Sprintf("SD card log subcommand %d", p[0]),
			Msg: "An SD card log packet of a subcommand this codec does not read was passed over."}}
	}
	return nil
}

// files reads a files packet (37): subcommand, source, then the
// subcommand's answer.
func (c *codec) files(p []byte, m *track.Message) error {
	if len(p) < 3 {
		return short("files")
	}
	sub, src, p := p[0], int(p[1]), p[2:]
	m.Kind = "response"
	text := ""
	switch sub {
	case 0:
		if len(p) < 2 {
			return short("file count")
		}
		n := int(binary.BigEndian.Uint16(p))
		text, m.Details = fmt.Sprintf("%d files", n), map[string]any{"fileCount": n, "source": src}
	case 1:
		n := int(p[0])
		if len(p) < 1+8*n {
			return short("file list")
		}
		names := make([]string, n)
		for i := range names {
			names[i] = strings.TrimRight(string(p[1+8*i:9+8*i]), " \x00")
		}
		text, m.Details = strings.Join(names, " "), map[string]any{"files": names, "source": src}
	case 2:
		return c.filePacket(src, p, m)
	case 3:
		if len(p) < 9 {
			return short("file delete")
		}
		name := strings.TrimRight(string(p[:8]), " \x00")
		text, m.Failed = "deleted "+name, p[8] != 1
		if m.Failed {
			text = "could not delete " + name
		}
	case 4:
		text, m.Failed = "files deleted", p[0] != 1
		if m.Failed {
			text = "could not delete the files"
		}
	default:
		return &track.Skip{Warning: track.Warning{Code: "unknownMessage", Detail: fmt.Sprintf("files subcommand %d", sub),
			Msg: "A files packet of a subcommand this codec does not read was passed over."}}
	}
	m.Response = &text
	return nil
}

// filePacket reassembles a file: name (8), packet count (2), packet number
// (2), data. The device sends one packet per request, so the codec asks
// for the next one.
func (c *codec) filePacket(src int, p []byte, m *track.Message) error {
	if len(p) < 12 {
		return short("file transfer")
	}
	rawName := p[:8]
	total, idx := int(binary.BigEndian.Uint16(p[8:10])), int(binary.BigEndian.Uint16(p[10:12]))
	data := p[12:]
	name := strings.TrimRight(string(rawName), " \x00")
	if rawName[0] == 0xFF || total == 0 || idx >= total {
		text := "the device has no such file or packet"
		m.Response, m.Failed = &text, true
		return nil
	}
	if c.pic == nil || c.pic.name != name || c.pic.total != total || c.pic.source != src {
		c.pic = &assembly{name: name, source: src, total: total, parts: map[int][]byte{}}
	}
	a := c.pic
	if old, dup := a.parts[idx]; dup {
		a.size -= len(old)
	}
	a.parts[idx] = data
	a.size += len(data)
	if a.size > MaxPicture {
		c.pic = nil
		return &track.Skip{Warning: track.Warning{Code: "pictureTooLarge", Detail: name,
			Msg: fmt.Sprintf("A file larger than %d bytes was dropped; its packets are no longer requested.", MaxPicture)}}
	}
	text := fmt.Sprintf("file %s packet %d of %d", name, idx+1, total)
	m.Kind, m.Response = "picture", &text
	m.Details = map[string]any{"fileName": name, "source": src, "packets": total, "packet": idx}
	if len(a.parts) == total {
		out := make([]byte, 0, a.size)
		for i := 0; i < total; i++ {
			out = append(out, a.parts[i]...)
		}
		m.Details["picture"] = &Picture{Name: name, Source: src, Data: out}
		m.Details["pictureSize"] = len(out)
		c.pic = nil
		return nil
	}
	next := 0
	for next < total && a.parts[next] != nil {
		next++
	}
	m.Reply = FileRequest(src, string(rawName), next)
	return nil
}

// FileRequest asks for packet n of a file (137, subcommand 2).
func FileRequest(source int, name string, n int) []byte {
	b := append([]byte{2, byte(source)}, name...)
	return ServerFrame(Files, binary.BigEndian.AppendUint16(b, uint16(n)))
}

// FileListRequest asks for the names of the files made between from and
// to (Unix seconds; 137, subcommand 1).
func FileListRequest(source int, from, to uint32) []byte {
	b := binary.BigEndian.AppendUint32([]byte{1, byte(source)}, from)
	return ServerFrame(Files, binary.BigEndian.AppendUint32(b, to))
}

// ---- the protocol's own command forms ---------------------------------------

// binaryForms are the command forms that are not SMS text.
var binaryForms = []string{"setIo", "getVersion", "setConnection", "setOdometer", "photoList", "photo"}

func binaryForm(content any) (string, any, int, bool) {
	m, ok := content.(map[string]any)
	if !ok {
		return "", nil, 0, false
	}
	for _, k := range binaryForms {
		if v, has := m[k]; has {
			return k, v, len(m), true
		}
	}
	return "", nil, 0, false
}

func object(form string, v any, members int, allowed ...string) (map[string]any, error) {
	o, ok := v.(map[string]any)
	if members != 1 || (!ok && v != nil && v != true) {
		return nil, fmt.Errorf("%s is {\"%s\": {%s}} alone", form, form, strings.Join(allowed, ", "))
	}
	for k := range o {
		found := false
		for _, a := range allowed {
			found = found || a == k
		}
		if !found {
			return nil, fmt.Errorf("%s has no member %q (members: %s)", form, k, strings.Join(allowed, ", "))
		}
	}
	return o, nil
}

// binaryCommand frames the protocol's own forms:
//
//	{"getVersion": {}}                                       103, answered with 3
//	{"setConnection": {"host": h, "port": p, "protocol": "TCP"}}  105, not answered (used once)
//	{"setOdometer": {"value": metres}}                       106, not answered (the next record shows it)
//	{"photoList": {"source": 0, "from": 0, "to": 2147483647}}   137 subcommand 1, answered with 37
//	{"photo": {"name": "5DDA1FAD", "source": 0}}             137 subcommand 2 from packet 0; the codec asks for the rest
func binaryCommand(form string, v any, members int) ([]byte, bool, error) {
	switch form {
	case "getVersion":
		if _, err := object(form, v, members); err != nil {
			return nil, false, err
		}
		return ServerFrame(GetVersion, nil), true, nil
	case "setConnection":
		o, err := object(form, v, members, "host", "port", "protocol")
		if err != nil {
			return nil, false, err
		}
		host, _ := o["host"].(string)
		port, okPort := whole(o["port"], 65535)
		proto := "TCP"
		if s, ok := o["protocol"].(string); ok {
			proto = strings.ToUpper(s)
		}
		if host == "" || strings.ContainsAny(host, ", ") || !okPort || port < 1 || (proto != "TCP" && proto != "UDP") {
			return nil, false, errors.New(`setConnection is {"host": "<name or address>", "port": 1 to 65535, "protocol": "TCP" or "UDP"}`)
		}
		return ServerFrame(SetConnection, []byte(host+","+strconv.Itoa(int(port))+","+proto)), false, nil
	case "setOdometer":
		o, err := object(form, v, members, "value")
		if err != nil {
			return nil, false, err
		}
		val, ok := whole(o["value"], 4294967295)
		if !ok {
			return nil, false, errors.New(`setOdometer is {"value": <metres, 0 to 4294967295>}`)
		}
		return ServerFrame(SetOdometer, binary.BigEndian.AppendUint32(nil, uint32(val))), false, nil
	case "photoList":
		o, err := object(form, v, members, "source", "from", "to")
		if err != nil {
			return nil, false, err
		}
		src, ok1 := whole(orZero(o["source"]), 5)
		from, ok2 := whole(orZero(o["from"]), 4294967295)
		to := float64(0x7FFFFFFF)
		ok3 := true
		if t, has := o["to"]; has {
			to, ok3 = whole(t, 4294967295)
		}
		if !ok1 || !ok2 || !ok3 {
			return nil, false, errors.New(`photoList is {"source": 0 to 5, "from": <Unix seconds>, "to": <Unix seconds>}`)
		}
		return FileListRequest(int(src), uint32(from), uint32(to)), true, nil
	case "photo":
		o, err := object(form, v, members, "name", "source")
		if err != nil {
			return nil, false, err
		}
		name, _ := o["name"].(string)
		src, ok := whole(orZero(o["source"]), 5)
		if len(name) == 0 || len(name) > 8 || !ok {
			return nil, false, errors.New(`photo is {"name": "<file name, up to 8 characters>", "source": 0 to 5}`)
		}
		return FileRequest(int(src), fmt.Sprintf("%-8s", name), 0), true, nil
	}
	return nil, false, fmt.Errorf("unknown form %s", form)
}

func orZero(v any) any {
	if v == nil {
		return float64(0)
	}
	return v
}
