// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package eelink

import (
	"encoding/binary"
	"errors"

	"github.com/cB-Sigma/trackers/track"
)

// Named commands as Eelink device commands (Device Protocol V2.0,
// sections RELAY, WHERE, RESET and COLLECT).
var (
	namedDefaults = map[string]string{
		track.ActionEngineStop:   "RELAY,1#",
		track.ActionEngineResume: "RELAY,0#",
		track.ActionLocate:       "WHERE#",
		track.ActionReboot:       "RESET#",
		track.ActionInterval:     "COLLECT,{seconds},0,0,0,1#",
	}
	// Interval bounds the interval command, in seconds.
	Interval = track.IntervalRange{Min: 1, Max: 86400}
	// NamedActions are the named commands Eelink has: all of them.
	NamedActions = track.Actions
)

func (c *codec) text(imei string, content any) (string, error) {
	n, ok, err := track.ReadNamed(content)
	if err != nil {
		return "", err
	}
	if ok {
		return track.NamedText("eelink", n, c.cfg.named, namedDefaults, Interval, imei, "")
	}
	return track.CommandText(content)
}

// InstructionFrame builds a 0x80 instruction package of type 1 (a device
// command) with uid and the command text.
func InstructionFrame(seq uint16, uid uint32, text string) []byte {
	b := binary.BigEndian.AppendUint32([]byte{0x01}, uid)
	return Encode(PInstruction, seq, append(b, text...))
}

// Command frames {"text": "WHERE#"} or a named command as an instruction
// with the sequence as UID; over UDP inside the datagram header.
func (c *codec) Command(imei string, content any, seq uint32) ([]byte, bool, error) {
	s, err := c.text(imei, content)
	if err != nil {
		return nil, false, err
	}
	if len(s) > 1000 {
		return nil, false, errors.New("an Eelink command is at most 1000 bytes")
	}
	f := InstructionFrame(uint16(seq), seq, s)
	if c.udp {
		if imei == "" {
			imei = c.imei
		}
		f = Datagram(c.mark, imei, f)
	}
	return f, true, nil
}

// Correlation: the answer repeats the UID, the sequence; a zero UID
// names no command.
func (c *codec) Correlation(_ any, seq uint32) (string, bool) {
	return uidCorrelation(seq), false
}
