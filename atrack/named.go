// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package atrack

import (
	"errors"
	"strconv"
	"strings"

	"github.com/cB-Sigma/trackers/track"
)

// Named commands as ATrack AT commands (protocol document 1.3.6:
// AT$OUTC, AT$GPOS, AT$REST, AT$TRAC).
var (
	namedDefaults = map[string]string{
		track.ActionEngineStop:   "AT$OUTC=1,1",
		track.ActionEngineResume: "AT$OUTC=1,0",
		track.ActionLocate:       "AT$GPOS",
		track.ActionReboot:       "AT$REST=1,0",
		track.ActionInterval:     "AT$TRAC=1,{seconds}",
	}
	// Interval bounds the interval command, in seconds (AT$TRAC's time is
	// a 16-bit count of seconds).
	Interval = track.IntervalRange{Min: 1, Max: 65535}
	// NamedActions are the named commands ATrack has: all of them.
	NamedActions = track.Actions
)

// text resolves content to the command line (without CR LF), the tag the
// answer will repeat ("" none) and whether the device answers in text.
func (c *codec) text(imei, password string, content any, seq uint32) (string, string, bool, error) {
	if password == "" {
		password = c.cfg.pass
	}
	n, named, err := track.ReadNamed(content)
	if err != nil {
		return "", "", false, err
	}
	var s string
	if named {
		tmpl, _ := c.cfg.named.Template(n.Action, namedDefaults[n.Action])
		s, err = track.NamedText("atrack", n, c.cfg.named, namedDefaults, Interval, imei, password)
		if err != nil {
			return "", "", false, err
		}
		if password != "" && !strings.Contains(tmpl, "{password}") {
			s = withPassword(s, password)
		}
	} else if s, err = track.CommandText(content); err != nil {
		return "", "", false, err
	}
	if strings.ContainsAny(s, "\r\n") {
		return "", "", false, errors.New("an ATrack command is one line: it cannot contain a line break")
	}
	s, tag := c.tagged(s, seq)
	answers := !strings.HasPrefix(strings.ToUpper(s), "AT$GPOS")
	return s, tag, answers, nil
}

// withPassword puts the password before the parameters.
func withPassword(s, password string) string {
	if name, params, ok := strings.Cut(s, "="); ok {
		return name + "=" + password + "," + params
	}
	return s + "=" + password
}

// tagged adds the sequence as tag to an AT$ command, or reads the tag the
// command already has.
func (c *codec) tagged(s string, seq uint32) (string, string) {
	if !c.cfg.tag || !strings.HasPrefix(strings.ToUpper(s), "AT$") {
		return s, ""
	}
	name, rest, hasEq := strings.Cut(s, "=")
	if i := strings.IndexByte(name, '+'); i >= 0 {
		return s, name[i+1:]
	}
	tag := strconv.FormatUint(uint64(seq%100000), 10)
	name += "+" + tag
	if hasEq {
		return name + "=" + rest, tag
	}
	return name, tag
}

func (c *codec) Command(imei string, content any, seq uint32) ([]byte, bool, error) {
	return c.CommandWithPassword(imei, "", content, seq)
}

// CommandWithPassword frames a command with the device's AT$PASS password
// before the parameters of a named command ("" uses the profile's).
func (c *codec) CommandWithPassword(imei, password string, content any, seq uint32) ([]byte, bool, error) {
	s, _, answers, err := c.text(imei, password, content, seq)
	if err != nil {
		return nil, false, err
	}
	return []byte(s + "\r\n"), answers, nil
}

// Correlation is the tag the answer repeats; an untagged answer is taken
// too (firmware that drops tags).
func (c *codec) Correlation(content any, seq uint32) (string, bool) {
	_, tag, _, err := c.text("", "", content, seq)
	if err != nil {
		return "", false
	}
	return tag, false
}
