// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package meitrack

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/cB-Sigma/trackers/track"
)

// Camera pictures (MEITRACK GPRS Protocol V1.8 sections 3.48 to 3.51, on the
// MVT600, T1, T333 and T3): the tracker keeps pictures on its memory card;
// D01 lists their names, D00,<name>,<start> asks for one from packet
// <start>, and the tracker answers with eight packets
// "D00,<name>,<packets>,<packet number>,<data>" in a row. The codec
// reassembles them per connection and asks for the next eight itself after
// every eighth packet (the document has the server ask about two seconds
// later; the codec's Reply goes at once). The last packet's message carries
// the picture (PictureOf).

// MaxPicture bounds a reassembled picture; a larger one is dropped with a
// warning.
const MaxPicture = 4 << 20

// maxPicturePackets bounds a picture's packet count.
const maxPicturePackets = 65535

// Picture is a camera picture a tracker sent in D00 packets.
type Picture struct {
	Name string // the file name on the tracker's memory card
	Data []byte // the picture file (JPEG)
}

// PicturePacket is one D00 packet's fields.
type PicturePacket struct {
	Name  string
	Total int // the picture's packet count
	Index int // this packet's number, from 0
	Data  []byte
}

// ParsePicturePacket reads a D00 packet's data (what follows "D00,"). The
// document calls the picture data hexadecimal; trackers send the bytes as
// they are, so data that is all hexadecimal digits is decoded and other
// data is taken as is.
func ParsePicturePacket(b []byte) (PicturePacket, error) {
	var p PicturePacket
	parts := bytes.SplitN(b, []byte{','}, 4)
	if len(parts) != 4 || len(parts[0]) == 0 {
		return p, errors.New("a D00 packet is <name>,<packets>,<packet number>,<data>")
	}
	p.Name = string(parts[0])
	total, e1 := strconv.Atoi(string(parts[1]))
	idx, e2 := strconv.Atoi(string(parts[2]))
	if e1 != nil || e2 != nil || total < 1 || total > maxPicturePackets || idx < 0 || idx >= total {
		return p, fmt.Errorf("D00 packet %q of %q is not a packet number within the count", parts[2], parts[1])
	}
	p.Total, p.Index, p.Data = total, idx, parts[3]
	if isHexText(p.Data) {
		if d, err := hex.DecodeString(string(p.Data)); err == nil {
			p.Data = d
		}
	}
	return p, nil
}

func isHexText(b []byte) bool {
	if len(b) == 0 || len(b)%2 != 0 {
		return false
	}
	for _, c := range b {
		if !(c >= '0' && c <= '9' || c >= 'A' && c <= 'F' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// PictureRequest is the command text asking for a picture's packets from
// start (0 for the whole picture): D00,<name>,<start>.
func PictureRequest(name string, start int) string {
	return "D00," + name + "," + strconv.Itoa(start)
}

// PictureListRequest is the command text asking for the picture list from
// packet start: D01,<start>.
func PictureListRequest(start int) string { return "D01," + strconv.Itoa(start) }

// PictureOf returns the picture a decoded message carries: the last D00
// packet's message holds the whole picture.
func PictureOf(m *track.Message) (*Picture, bool) {
	if m == nil {
		return nil, false
	}
	p, ok := m.Details["picture"].(*Picture)
	return p, ok
}

// assembly is a picture being received.
type assembly struct {
	name  string
	total int
	parts map[int][]byte
	size  int
}

// listAssembly is a picture list being received.
type listAssembly struct {
	total int
	parts map[int]string
}

func (c *codec) picturePacket(f *Frame, m *track.Message) error {
	p, err := ParsePicturePacket(f.Data)
	if err != nil {
		return &track.Skip{Warning: track.Warning{Code: "fieldUnreadable", Detail: err.Error(),
			Msg: "A picture packet (D00) whose fields could not be read was passed over."}}
	}
	if c.pic == nil || c.pic.name != p.Name || c.pic.total != p.Total {
		c.pic = &assembly{name: p.Name, total: p.Total, parts: map[int][]byte{}}
	}
	a := c.pic
	if old, dup := a.parts[p.Index]; dup {
		a.size -= len(old)
	}
	a.parts[p.Index] = p.Data
	a.size += len(p.Data)
	if a.size > MaxPicture || p.Total*len(p.Data) > 2*MaxPicture {
		c.pic = nil
		return &track.Skip{Warning: track.Warning{Code: "pictureTooLarge", Detail: p.Name,
			Msg: fmt.Sprintf("A picture larger than %d bytes was dropped; its packets are no longer requested.", MaxPicture)}}
	}
	text := fmt.Sprintf("D00,%s,%d,%d", p.Name, p.Total, p.Index)
	m.Response, m.Kind, m.Correlation = &text, "picture", c.correlation(f.ID, "D00")
	m.Details = map[string]any{"pictureName": p.Name, "packets": p.Total, "packet": p.Index}
	if len(a.parts) == a.total {
		data := make([]byte, 0, a.size)
		for i := 0; i < a.total; i++ {
			data = append(data, a.parts[i]...)
		}
		m.Details["picture"] = &Picture{Name: a.name, Data: data}
		m.Details["pictureSize"] = len(data)
		c.pic = nil
		return nil
	}
	if next := p.Index + 1; next%8 == 0 && next < p.Total {
		m.Reply = Encode(true, f.ID, f.IMEI, []byte(PictureRequest(p.Name, next)))
	}
	return nil
}

// pictureList reads a D01 packet: "<packets>,<packet number>,<names>"; the
// names, separated by '|', run on from one packet to the next.
func (c *codec) pictureList(f *Frame, m *track.Message) {
	text := "D01," + string(f.Data)
	m.Response, m.Kind, m.Correlation = &text, "response", c.correlation(f.ID, "D01")
	parts := strings.SplitN(string(f.Data), ",", 3)
	if len(parts) != 3 {
		return
	}
	total, e1 := strconv.Atoi(parts[0])
	idx, e2 := strconv.Atoi(parts[1])
	if e1 != nil || e2 != nil || total < 1 || total > maxPicturePackets || idx < 0 || idx >= total {
		return
	}
	m.Details = map[string]any{"packets": total, "packet": idx}
	if c.list == nil || c.list.total != total {
		c.list = &listAssembly{total: total, parts: map[int]string{}}
	}
	c.list.parts[idx] = parts[2]
	if len(c.list.parts) < total {
		return
	}
	var all strings.Builder
	for i := 0; i < total; i++ {
		all.WriteString(c.list.parts[i])
	}
	var names []string
	for _, n := range strings.Split(all.String(), "|") {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}
	m.Details["pictures"] = names
	c.list = nil
}
