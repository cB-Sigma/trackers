// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package suntech

import (
	"errors"
	"strings"

	"github.com/cB-Sigma/trackers/track"
)

// Named commands of the Universal protocol (group;action) and of the older
// protocol (the action word after "02"), without the device ID.
var (
	universalNamed = map[string]string{
		track.ActionEngineStop:   "04;01",
		track.ActionEngineResume: "04;02",
		track.ActionLocate:       "03;01",
		track.ActionReboot:       "03;03",
	}
	legacyNamed = map[string]string{
		track.ActionEngineStop:   "Enable1",
		track.ActionEngineResume: "Disable1",
		track.ActionLocate:       "StatusReq",
		track.ActionReboot:       "Reboot",
	}
)

// form is the protocol commands go out in: universal, or the older one
// with its model prefix.
func (c *codec) form() (universal bool, prefix string, err error) {
	switch {
	case c.known:
		return c.universal, c.prefix, nil
	case c.cfg.format == "universal":
		return true, "", nil
	case c.cfg.model != "":
		return false, c.cfg.model, nil
	}
	return false, "", errors.New("suntech: the device's protocol is not known before its first report; send the command after it, or set profile.format (and profile.model for the older protocol)")
}

// defaults are the named command texts for this connection, with {imei}.
func (c *codec) defaults() (map[string]string, error) {
	universal, prefix, err := c.form()
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for a, v := range universalNamed {
		if universal {
			out[a] = "CMD;{imei};" + v
		} else {
			out[a] = prefix + "CMD;{imei};02;" + legacyNamed[a]
		}
	}
	return out, nil
}

// Command frames a command; every command is answered.
func (c *codec) Command(imei string, content any, _ uint32) ([]byte, bool, error) {
	n, named, err := track.ReadNamed(content)
	if err != nil {
		return nil, false, err
	}
	if named {
		def := map[string]string{}
		if _, set := c.cfg.named[n.Action]; !set {
			if def, err = c.defaults(); err != nil {
				return nil, false, err
			}
		}
		if n.Action == track.ActionInterval {
			if _, set := c.cfg.named[n.Action]; !set {
				return nil, false, track.Unsupported("suntech", n.Action,
					"the reporting intervals are set by a parameter command whose layout differs by model; set profile.namedCommands.interval to the device's command text with {imei} and {seconds}")
			}
		}
		text, err := track.NamedText("suntech", n, c.cfg.named, def, Interval, imei, "")
		if err != nil {
			return nil, false, err
		}
		return []byte(text + "\r"), true, nil
	}
	text, err := track.CommandText(content)
	if err != nil {
		return nil, false, errors.New(`a command is {"text": "CMD;<id>;04;01"} (or ST300CMD;<id>;02;Enable1 on the older protocol) or {"action": …}`)
	}
	text = strings.TrimSuffix(text, "\r")
	if strings.ContainsAny(text, "\r\n") {
		return nil, false, errors.New("a Suntech command is one line; only a final carriage return is allowed")
	}
	if len(text) > 512 {
		return nil, false, errors.New("a Suntech command is at most 512 characters")
	}
	return []byte(text + "\r"), true, nil
}

// Correlation: the answer names the command (the older protocol's action
// word, the Universal protocol's group and action). A text command is
// correlated when it is a CMD.
func (c *codec) Correlation(content any, seq uint32) (string, bool) {
	var text string
	if n, named, err := track.ReadNamed(content); named {
		if err != nil {
			return "", false
		}
		def, _ := c.defaults()
		tmpl, ok := c.cfg.named.Template(n.Action, def[n.Action])
		if !ok {
			return "", false
		}
		text = track.Expand(tmpl, n, "", "")
	} else if t, err := track.CommandText(content); err == nil {
		text = strings.TrimSuffix(t, "\r")
	}
	f := strings.Split(text, ";")
	if len(f) < 4 || !strings.HasSuffix(f[0], "CMD") {
		return "", false
	}
	if f[0] == "CMD" {
		return f[2] + ";" + f[3], true
	}
	return f[3], true
}
