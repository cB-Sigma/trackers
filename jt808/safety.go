// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package jt808

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/cB-Sigma/trackers/track"
)

// Active safety ("Su-Biao") extension: the location additional items of
// ADAS (0x64), driver state monitoring (0x65), tyre pressure (0x66) and
// blind spot (0x67) terminals, and the alarm attachment messages 0x1210,
// 0x1211 and 0x1212 (answered 0x8001, 0x8001 and 0x9212). Layouts as the
// Jiangsu standard T/JSATL12-2017 describes them, in the form the public
// implementations read (an alarm label of 16 bytes with a 7-byte terminal
// ID; the Guangdong form, 40 bytes with a 30-byte ID, is also read).
//
// Every item opens with the alarm ID (4 bytes) and a state byte (0 an
// event without start or end, 1 started, 2 ended) and closes with the
// position block (speed, altitude, latitude, longitude, time, vehicle
// status: 19 bytes, already in the location's basic block) and the alarm
// label, which names the alarm's attachments (terminal ID, BCD[6] time,
// serial, attachment count, reserved). An alarm that starts or an event
// becomes an alert; its end does not.

// Message IDs of the active safety extension.
const (
	MAlarmAttachments = 0x1210
	MFileInfo         = 0x1211
	MFileDone         = 0x1212
	MAttachmentUpload = 0x9208
	MFileDoneAnswer   = 0x9212
)

// fileMagic opens an attachment data packet ("01cd"), sent to the
// attachment server outside the JT808 framing.
var fileMagic = []byte{0x30, 0x31, 0x63, 0x64}

var adasTypes = map[byte]string{
	0x01: "forward-collision-warning",
	0x02: "lane-departure-warning",
	0x03: "headway-warning",
	0x04: "pedestrian-collision-warning",
	0x05: "frequent-lane-change",
	0x06: "road-sign-over-limit",
	0x07: "obstacle-warning",
	0x10: "road-sign-recognized",
	0x11: "adas-capture",
}

var dsmTypes = map[byte]string{
	0x01: "fatigue-driving",
	0x02: "phone-use",
	0x03: "smoking",
	0x04: "distracted-driving",
	0x05: "driver-absent",
	0x10: "dsm-capture",
	0x11: "driver-changed",
}

var bsdTypes = map[byte]string{
	0x01: "blind-spot-rear",
	0x02: "blind-spot-left-rear",
	0x03: "blind-spot-right-rear",
}

// tpmsBits are the alarm bits of a tyre in item 0x66.
var tpmsBits = []string{
	"tyre-pressure-high",
	"tyre-pressure-low",
	"tyre-temperature-high",
	"tyre-sensor-fault",
	"tyre-pressure-imbalance",
	"tyre-slow-leak",
	"tyre-sensor-low-battery",
}

var states = []string{"event", "start", "end"}

func stateName(b byte) string {
	if int(b) < len(states) {
		return states[b]
	}
	return fmt.Sprintf("state%d", b)
}

// label reads an alarm label (16 bytes with a 7-byte terminal ID, or 40
// with 30) into status values under prefix.
func label(st map[string]any, prefix string, b []byte) {
	st[prefix+"Label"] = fmt.Sprintf("%X", b)
	if len(b) < 16 {
		return
	}
	id := 7
	if len(b) >= 40 {
		id = 30
	}
	st[prefix+"Terminal"] = gbkText(b[:id])
	st[prefix+"Attachments"] = int(b[id+7])
}

// safetyAlert is an alert of a safety item: level 2 is major, level 1
// minor, an event (type 0x10 and up) information.
func safetyAlert(item, typ byte, name string, id uint32, level byte) track.Alert {
	sev := track.Minor
	switch {
	case typ >= 0x10:
		sev = track.Info
	case level >= 2:
		sev = track.Major
	}
	return track.Alert{Type: name, Severity: sev, Code: fmt.Sprintf("0x%02X-0x%02X#%d", item, typ, id)}
}

// safetyItem reads item 0x64 to 0x67 into status values and alerts; ok is
// false when the item does not have the extension's layout (vendors use
// these IDs for other things), and it is then kept as hexadecimal.
func safetyItem(id byte, v []byte, st map[string]any) ([]track.Alert, bool) {
	const pos = 19 // speed .. vehicle status at the end, before the label
	switch id {
	case 0x64, 0x65:
		if len(v) < 31+16 {
			return nil, false
		}
		p := "adas"
		names := adasTypes
		if id == 0x65 {
			p, names = "dsm", dsmTypes
		}
		aid, state, typ, level := binary.BigEndian.Uint32(v), v[4], v[5], v[6]
		st[p+"AlarmId"] = aid
		st[p+"State"] = stateName(state)
		st[p+"Alarm"] = int(typ)
		st[p+"Level"] = int(level)
		if id == 0x64 {
			st["adasFrontSpeed"] = int(v[7])    // km/h
			st["adasFrontDistance"] = int(v[8]) // 100 ms
			st["adasDeparture"] = int(v[9])     // 1 left, 2 right
			st["adasRoadSign"] = int(v[10])
			st["adasRoadSignValue"] = int(v[11])
			label(st, p, v[12+pos:])
		} else {
			st["dsmFatigue"] = int(v[7])
			label(st, p, v[12+pos:])
		}
		if state == 2 {
			return nil, true
		}
		name, ok := names[typ]
		if !ok {
			name = fmt.Sprintf("%s-0x%02X", p, typ)
		}
		return []track.Alert{safetyAlert(id, typ, name, aid, level)}, true
	case 0x66:
		// ID, state, position block, label, tyre count, tyres of 9 bytes.
		for _, lb := range []int{16, 40} {
			if len(v) < 5+pos+lb+1 {
				continue
			}
			n := int(v[5+pos+lb])
			if len(v) != 5+pos+lb+1+9*n {
				continue
			}
			aid, state := binary.BigEndian.Uint32(v), v[4]
			st["tpmsAlarmId"] = aid
			st["tpmsState"] = stateName(state)
			label(st, "tpms", v[5+pos:5+pos+lb])
			var out []track.Alert
			for t := v[5+pos+lb+1:]; len(t) >= 9; t = t[9:] {
				tyre, bits := int(t[0]), binary.BigEndian.Uint16(t[1:])
				k := fmt.Sprintf("tyre%d", tyre)
				st[k+"Pressure"] = int(binary.BigEndian.Uint16(t[3:]))    // kPa
				st[k+"Temperature"] = int(binary.BigEndian.Uint16(t[5:])) // °C
				st[k+"Battery"] = int(binary.BigEndian.Uint16(t[7:]))     // %
				st[k+"Alarms"] = int(bits)
				for b, name := range tpmsBits {
					if bits&(1<<b) != 0 && state != 2 {
						sev := track.Minor
						if b == 2 || b == 5 {
							sev = track.Major
						}
						out = append(out, track.Alert{Type: name, Severity: sev, Code: fmt.Sprintf("0x66-tyre%d-bit%d#%d", tyre, b, aid)})
					}
				}
			}
			return out, true
		}
		return nil, false
	case 0x67:
		if len(v) != 6+pos+16 && len(v) != 6+pos+40 {
			return nil, false
		}
		aid, state, typ := binary.BigEndian.Uint32(v), v[4], v[5]
		st["bsdAlarmId"] = aid
		st["bsdState"] = stateName(state)
		st["bsdAlarm"] = int(typ)
		label(st, "bsd", v[6+pos:])
		if state == 2 {
			return nil, true
		}
		name, ok := bsdTypes[typ]
		if !ok {
			name = fmt.Sprintf("bsd-0x%02X", typ)
		}
		return []track.Alert{safetyAlert(id, typ, name, aid, 1)}, true
	}
	return nil, false
}

// SafetyAlerts are the alerts of the location's active safety items.
func (l *Location) SafetyAlerts() []track.Alert {
	var out []track.Alert
	for _, id := range []byte{0x64, 0x65, 0x66, 0x67} {
		if v, ok := l.Items[id]; ok {
			a, _ := safetyItem(id, v, map[string]any{})
			out = append(out, a...)
		}
	}
	return out
}

// Attachment is one file of an alarm (0x1210).
type Attachment struct {
	Name string
	Size uint32
}

// AlarmAttachments is a 0x1210 body.
type AlarmAttachments struct {
	Terminal string
	// Label is the alarm label of the location item (16 or 40 bytes).
	Label []byte
	// Number is the alarm number the platform gave in 0x9208.
	Number string
	// Supplement is true for information sent again (info type 1).
	Supplement bool
	Files      []Attachment
}

// ParseAlarmAttachments reads a 0x1210 body, with a 7-byte terminal ID and
// a 16-byte label or a 30-byte ID and a 40-byte label.
func ParseAlarmAttachments(b []byte) (*AlarmAttachments, error) {
	for _, f := range [][2]int{{7, 16}, {30, 40}} {
		p := f[0] + f[1] + 32 + 2
		if len(b) < p {
			continue
		}
		a := &AlarmAttachments{Terminal: gbkText(b[:f[0]]), Label: append([]byte(nil), b[f[0]:f[0]+f[1]]...),
			Number: gbkText(b[f[0]+f[1] : f[0]+f[1]+32]), Supplement: b[p-2] == 1}
		n, rest, ok := int(b[p-1]), b[p:], true
		for range n {
			if len(rest) < 1 || len(rest) < 1+int(rest[0])+4 {
				ok = false
				break
			}
			l := int(rest[0])
			a.Files = append(a.Files, Attachment{Name: gbkText(rest[1 : 1+l]), Size: binary.BigEndian.Uint32(rest[1+l:])})
			rest = rest[1+l+4:]
		}
		if ok && len(rest) == 0 {
			return a, nil
		}
	}
	return nil, fmt.Errorf("a 0x1210 body of %d bytes fits neither label form", len(b))
}

var fileTypes = []string{"picture", "audio", "video", "text", "other"}

// fileInfo reads a 0x1211 or 0x1212 body: name, type, size.
func fileInfo(b []byte) (name string, typ byte, size uint32, err error) {
	if len(b) < 1 || len(b) < 1+int(b[0])+5 {
		return "", 0, 0, fmt.Errorf("a file information body of %d bytes is cut short", len(b))
	}
	l := int(b[0])
	return string(b[1 : 1+l]), b[1+l], binary.BigEndian.Uint32(b[2+l:]), nil
}

func fileTypeName(t byte) string {
	if int(t) < len(fileTypes) {
		return fileTypes[t]
	}
	return fmt.Sprintf("type%d", t)
}

// attachmentMessage reads 0x1210, 0x1211 and 0x1212.
func (c *codec) attachmentMessage(f *Frame, m *track.Message) {
	m.Kind = "normal"
	switch f.ID {
	case MAlarmAttachments:
		m.Reply = c.general(f, ResultOK)
		a, err := ParseAlarmAttachments(f.Body)
		if err != nil {
			m.Warnings = append(m.Warnings, short(f, err))
			return
		}
		files := make([]any, len(a.Files))
		for i, x := range a.Files {
			files[i] = map[string]any{"name": x.Name, "size": x.Size}
		}
		m.Records = []track.Record{{Status: map[string]any{"attachmentAlarm": a.Number, "attachmentLabel": fmt.Sprintf("%X", a.Label),
			"attachmentTerminal": a.Terminal, "attachmentFiles": files, "attachmentSupplement": a.Supplement}}}
	case MFileInfo, MFileDone:
		name, typ, size, err := fileInfo(f.Body)
		if err != nil {
			m.Reply = c.general(f, ResultBadMessage)
			m.Warnings = append(m.Warnings, short(f, err))
			return
		}
		st := map[string]any{"attachmentFile": name, "attachmentType": fileTypeName(typ), "attachmentSize": size}
		if f.ID == MFileInfo {
			m.Reply = c.general(f, ResultOK)
			st["attachmentState"] = "sending"
		} else {
			// Upload complete, nothing to send again: this codec does
			// not keep the file data (see skipFileData).
			b := append([]byte{byte(len(name))}, name...)
			m.Reply = c.reply(MFileDoneAnswer, append(b, typ, 0, 0))
			st["attachmentState"] = "sent"
		}
		m.Records = []track.Record{{Status: st}}
	}
}

// skipFileData passes over an attachment data packet ("01cd", a 50-byte
// file name, offset and length, then the data) when one is next in r. The
// file data is not kept: a warning is given once per file.
func (c *codec) skipFileData(r *bufio.Reader) (bool, error) {
	if b, err := r.Peek(1); err != nil || b[0] != fileMagic[0] {
		return false, nil
	}
	h, err := r.Peek(62)
	if err != nil || string(h[:4]) != string(fileMagic) {
		return false, nil
	}
	name := gbkText(h[4:54])
	off, n := binary.BigEndian.Uint32(h[54:]), binary.BigEndian.Uint32(h[58:])
	if _, err := r.Discard(62); err != nil {
		return true, err
	}
	if _, err := r.Discard(int(n)); err != nil {
		return true, err
	}
	if c.lastFile == name {
		return true, track.ErrSkip
	}
	c.lastFile = name
	return true, &track.Skip{Warning: track.Warning{Code: "attachmentData", Detail: fmt.Sprintf("%s offset %d length %d", name, off, n),
		Msg: "Alarm attachment data (pictures, video) was passed over; this codec reads the attachment messages but does not store files."}}
}

// planAttachmentUpload frames {"op": "attachmentUpload", ...} as 0x9208:
// the attachment server, the alarm label of the location item and the
// alarm number the platform gives it.
func planAttachmentUpload(a args) (*planned, error) {
	srv, tcp, udp, err := a.server()
	if err != nil {
		return nil, err
	}
	lb, err := hex.DecodeString(a.str("alarmLabel"))
	if err != nil || (len(lb) != 16 && len(lb) != 40) {
		return nil, fmt.Errorf(`attachmentUpload needs "alarmLabel", the 16- or 40-byte label of the alarm item in hexadecimal`)
	}
	num := a.str("alarmNumber")
	if num == "" {
		num = fmt.Sprintf("%X", lb)
	}
	if len(num) > 32 {
		num = num[:32]
	}
	if err := a.done(); err != nil {
		return nil, err
	}
	b := append([]byte{byte(len(srv))}, srv...)
	b = binary.BigEndian.AppendUint16(b, uint16(tcp))
	b = binary.BigEndian.AppendUint16(b, uint16(udp))
	b = append(b, lb...)
	b = append(b, pad32(num)...)
	b = append(b, make([]byte, 16)...) // reserved
	return &planned{id: MAttachmentUpload, body: b}, nil
}

func pad32(s string) []byte {
	b := make([]byte, 32)
	copy(b, s)
	return b
}
