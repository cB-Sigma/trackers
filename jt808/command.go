package jt808

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/cB-Sigma/trackers/track"
)

// MaxText is the longest text command (the body length field allows 1023
// bytes, less the flag bytes).
const MaxText = 1000

// Terminal control (0x8105) command words.
const (
	CtrlReset       = 0x04 // terminal reset (JT/T 808-2013 table 18)
	CtrlEngineStop  = 0xF0 // vendor form, engineControl terminalControl
	CtrlEngineStart = 0xF1
)

// ParamReportInterval is the 0x8103 parameter of the default time report
// interval, in seconds (JT/T 808-2013 table 12).
const ParamReportInterval = 0x0029

// engineText are the Jimi text commands of engineControl "text".
var engineText = map[string]string{track.ActionEngineStop: "RELAY,1#", track.ActionEngineResume: "RELAY,0#"}

// planned is a command ready to frame.
type planned struct {
	id   uint16
	body []byte
	text bool
	// cut is the fuel line state a 0x8500 command asks for.
	cut *bool
	// plain is never encrypted (the key exchange).
	plain bool
}

func (c *codec) v2019() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.known && c.version >= 0
}

// plan maps a command's content to its message.
func (c *codec) plan(imei string, content any) (*planned, error) {
	n, named, err := track.ReadNamed(content)
	if err != nil {
		return nil, err
	}
	if m, ok := content.(map[string]any); ok && !named {
		if _, isOp := m["op"]; isOp {
			return c.planOp(m)
		}
	}
	if !named {
		text, err := track.CommandText(content)
		if err != nil {
			return nil, err
		}
		return c.textCommand(text)
	}
	if n.Action == track.ActionInterval {
		if err := Interval.Check(n.Seconds); err != nil {
			return nil, err
		}
	}
	def := map[string]string{}
	if c.cfg.engine == "text" {
		def = engineText
	}
	if _, set := c.cfg.named[n.Action]; set || def[n.Action] != "" {
		text, err := track.NamedText("jt808", n, c.cfg.named, def, Interval, imei, "")
		if err != nil {
			return nil, err
		}
		return c.textCommand(text)
	}
	switch n.Action {
	case track.ActionEngineStop, track.ActionEngineResume:
		stop := n.Action == track.ActionEngineStop
		if c.cfg.engine == "terminalControl" {
			w := byte(CtrlEngineStart)
			if stop {
				w = CtrlEngineStop
			}
			return &planned{id: MTerminalControl, body: []byte{w}}, nil
		}
		flag := byte(0)
		if stop {
			flag = 1
		}
		body := []byte{flag}
		if c.v2019() {
			// 2019 form: one control item, type 0x0001, its parameter.
			body = []byte{0x00, 0x01, 0x00, 0x01, flag}
		}
		return &planned{id: MVehicleControl, body: body, cut: &stop}, nil
	case track.ActionLocate:
		return &planned{id: MLocate}, nil
	case track.ActionReboot:
		return &planned{id: MTerminalControl, body: []byte{CtrlReset}}, nil
	case track.ActionInterval:
		b := []byte{1}
		b = binary.BigEndian.AppendUint32(b, ParamReportInterval)
		b = append(b, 4)
		b = binary.BigEndian.AppendUint32(b, uint32(n.Seconds))
		return &planned{id: MSetParams, body: b}, nil
	}
	return nil, track.Unsupported("jt808", n.Action, "send it as text")
}

func (c *codec) textCommand(text string) (*planned, error) {
	if len(text) > MaxText {
		return nil, fmt.Errorf("a JT808 text command is at most %d characters", MaxText)
	}
	for i := 0; i < len(text); i++ {
		if text[i] < 0x20 || text[i] > 0x7E {
			return nil, errors.New("a JT808 text command is sent in printable ASCII only (the protocol's text is GBK); write it without other characters")
		}
	}
	if c.cfg.text8900 {
		return &planned{id: MDownlinkPass, body: append([]byte{0xF0}, text...), text: true}, nil
	}
	b := []byte{c.cfg.textFlag}
	if c.v2019() {
		b = append(b, 1) // text type: notice
	}
	return &planned{id: MText, body: append(b, text...), text: true}, nil
}

// header is a platform header in the connection's form, or a 2013 one
// made from the device's identifier before the device was heard.
func (c *codec) header(imei string, id uint16, serial uint16) Header {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.known {
		return Header{ID: id, Version: c.version, Phone: c.phone, Serial: serial}
	}
	return Header{ID: id, Version: -1, Phone: PhoneBCD(imei, 6), Serial: serial}
}

// Command frames a command; the platform serial is the low 16 bits of
// seq, and every JT808 command is answered.
func (c *codec) Command(imei string, content any, seq uint32) ([]byte, bool, error) {
	p, err := c.plan(imei, content)
	if err != nil {
		return nil, false, err
	}
	h := c.header(imei, p.id, uint16(seq))
	body := p.body
	if k := c.terminalKey(fmt.Sprintf("%X", h.Phone)); k != nil && c.cfg.encrypt && !p.plain && len(body) > 0 {
		if body, err = EncryptBody(k, body); err != nil {
			return nil, false, err
		}
		if len(body) > propLength {
			return nil, false, fmt.Errorf("the command is %d bytes encrypted, more than the 1023 a message holds; shorten it or set profile.encryptCommands false", len(body))
		}
		h.Props |= PropRSA
	}
	if p.cut != nil {
		c.expect(fmt.Sprintf("%X", h.Phone), h.Serial, *p.cut)
	}
	if p.id == MPlaybackRequest || p.id == MResourceQuery {
		c.listed(h.Serial, p.id)
	}
	return EncodeWith(h, body), true, nil
}

// answerSerial is the serial a command's answer names: 0 for those whose
// answers name none (0x9003, 0x8A00).
func answerSerial(id uint16, seq uint32) uint16 {
	if id == MAVAttributesQuery || id == MPlatformRSA {
		return 0
	}
	return uint16(seq)
}

// Correlation names the answer of a command: its message ID and serial,
// as the device's 0x0001 (and 0x0201, 0x0500) echo them. A text command
// awaiting its text answer (which names no command) takes an answer
// without a name.
func (c *codec) Correlation(content any, seq uint32) (string, bool) {
	p, err := c.plan("", content)
	if err != nil {
		return "", false
	}
	return correlation(p.id, answerSerial(p.id, seq)), !(p.text && c.cfg.awaitText)
}

// expect notes the fuel line state a vehicle control command asks for.
func (c *codec) expect(phone string, serial uint16, cut bool) {
	sh := c.cfg.sh
	sh.mu.Lock()
	defer sh.mu.Unlock()
	if len(sh.engine) > 1024 {
		clear(sh.engine)
	}
	sh.engine[fmt.Sprintf("%s#%d", trimPhone(phone), serial)] = cut
}

// expected is the fuel line state the command with this serial asked for.
func (c *codec) expected(phone string, serial uint16) (bool, bool) {
	sh := c.cfg.sh
	sh.mu.Lock()
	defer sh.mu.Unlock()
	k := fmt.Sprintf("%s#%d", trimPhone(phone), serial)
	v, ok := sh.engine[k]
	delete(sh.engine, k)
	return v, ok
}
