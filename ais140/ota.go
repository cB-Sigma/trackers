package ais140

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/cB-Sigma/trackers/track"
)

// Over-the-air commands as AIS-140 Amendment 3 fixes them (item 21, clause
// 4.3, Table 4D): "$<IMEI>,<password>,SET,<id>:<value>[,<id>:<value>…]",
// "…,GET,<id>[,<id>…]" or "…,CLR,<id>[,<id>…]", then '*', the checksum
// (item 18: XOR of the characters, here those between '$' and '*', two
// upper-case hex digits) and CR LF. A device takes at least five keys in
// one command, so more are refused. The device answers with a data packet
// of alert ID 12 (packet type OA) whose OTA response field is
// "(SOURCE|SET|<id>:<value>:<status>|…)", status 1 done and 0 failed.
//
// Command content (as decoded from JSON):
//
//	{"op": "GET", "param": "001"}                      # one key (ID or name)
//	{"op": "GET", "params": ["firmwareVersion", "023"]}
//	{"op": "SET", "param": "009", "value": "80"}
//	{"op": "SET", "values": {"pvtIp": "203.0.113.5", "pvtPort": "5023"}}
//	{"op": "CLR", "param": "overspeedLimit"}
//	{"op": "HCHK"} / {"op": "ACTV"}                    # SMS requests (SMSRequest; not framed here)
//	{"text": "…"}                                      # sent as it is
//
// Each ID must allow the operation (SET, GET, CLR columns) and this
// backend's role (profile.otaRole: P for the PVT server, the default, E for
// the emergency server; Table 4D's allowed sources). profile.otaExtraIds
// adds a manufacturer's own IDs, e.g. {"030": "SET,GET"}.

// OTAParam is one row of Table 4D.
type OTAParam struct {
	ID, Name      string
	Sources       string // P PVT server, E emergency server, C control centre number
	Set, Get, Clr bool
}

// OTAParams is Table 4D.
var OTAParams = []OTAParam{
	{"001", "firmwareVersion", "P", false, true, false},
	{"002", "pvtIp", "P", true, true, true},
	{"003", "pvtPort", "P", true, true, true},
	{"004", "emergencyIp", "P", true, true, true},
	{"005", "emergencyPort", "P", true, true, true},
	{"006", "controlCentreNumber", "P", true, true, true},
	{"007", "apn", "P", true, true, true},
	{"008", "sleepTime", "P", true, true, true},
	{"009", "overspeedLimit", "P", true, true, true},
	{"010", "harshAccelerationThreshold", "P", true, true, true},
	{"011", "harshBrakingThreshold", "P", true, true, true},
	{"012", "harshCorneringThreshold", "P", true, true, true},
	{"013", "vehicleRegistration", "P", true, true, true},
	{"014", "ignitionOnInterval", "P", true, true, true},
	{"015", "ignitionOffInterval", "P", true, true, true},
	{"016", "emergencyInterval", "P", true, true, true},
	{"017", "emergencyAutoClearTimeout", "P", true, true, true},
	{"018", "restart", "P", true, true, true},
	{"019", "imei", "P", false, true, false},
	{"020", "clearEmergency", "EC", false, false, true},
	{"021", "emergencySmsNumber", "PE", true, true, true},
	{"022", "signalStrength", "P", false, true, false},
	{"023", "rfidTag", "PE", false, true, false},
}

// RFIDTagParam is the ID that reads the trailer's RFID tag (3.1.1.28,
// 6.2.1.8).
const RFIDTagParam = "023"

func otaParam(key string, extra map[string]OTAParam) (OTAParam, bool) {
	for _, p := range OTAParams {
		if p.ID == key || strings.EqualFold(p.Name, key) {
			return p, true
		}
	}
	p, ok := extra[key]
	return p, ok
}

// otaCommand is a parsed command: an operation and its keys and values.
type otaCommand struct {
	op     string
	keys   []string
	values []string // SET only
}

// parseOTA reads command content in the standard form.
func (c *Config) parseOTA(content any) (*otaCommand, string, error) {
	var raw struct {
		Op     string            `json:"op"`
		Param  string            `json:"param"`
		Params []string          `json:"params"`
		Value  *string           `json:"value"`
		Values map[string]string `json:"values"`
		Text   string            `json:"text"`
	}
	switch v := content.(type) {
	case string:
		raw.Text = v
	default:
		b, _ := json.Marshal(v)
		if err := track.StrictJSON(b, &raw); err != nil {
			return nil, "", fmt.Errorf(`an AIS-140 command is {"op": "SET"|"GET"|"CLR", "param"|"params"|"values": …} or {"text": …}: %w`, err)
		}
	}
	if raw.Text != "" {
		if strings.ContainsAny(raw.Text, "\r\n") {
			return nil, "", errors.New("a command is one line")
		}
		return nil, raw.Text, nil
	}
	op := strings.ToUpper(raw.Op)
	if op != "SET" && op != "GET" && op != "CLR" {
		return nil, "", fmt.Errorf("op %q is not SET, GET or CLR", raw.Op)
	}
	cmd := &otaCommand{op: op}
	add := func(key, value string, hasValue bool) error {
		p, ok := otaParam(key, c.otaExtra)
		if !ok {
			return fmt.Errorf("%q is not a command ID of AIS-140 Table 4D (001 to 023, or its name) nor in profile.otaExtraIds", key)
		}
		allowed := map[string]bool{"SET": p.Set, "GET": p.Get, "CLR": p.Clr}[op]
		if !allowed {
			return fmt.Errorf("%s (%s) does not take %s", p.ID, p.Name, op)
		}
		if !strings.ContainsAny(p.Sources, c.otaRole) {
			return fmt.Errorf("%s (%s) is accepted only from %s, and this backend is %s (profile.otaRole)", p.ID, p.Name, sourceNames(p.Sources), sourceNames(c.otaRole))
		}
		if op == "SET" {
			if !hasValue || value == "" {
				return fmt.Errorf("SET %s needs a value", p.ID)
			}
			if strings.ContainsAny(value, ",*$\r\n") {
				return fmt.Errorf("the value of %s must not contain ',', '*', '$' or a line break", p.ID)
			}
			cmd.values = append(cmd.values, value)
		}
		cmd.keys = append(cmd.keys, p.ID)
		return nil
	}
	if raw.Param != "" {
		v := ""
		if raw.Value != nil {
			v = *raw.Value
		}
		if err := add(raw.Param, v, raw.Value != nil); err != nil {
			return nil, "", err
		}
	}
	for _, k := range raw.Params {
		if op == "SET" {
			return nil, "", errors.New(`SET takes "param" and "value", or "values"`)
		}
		if err := add(k, "", false); err != nil {
			return nil, "", err
		}
	}
	keys := make([]string, 0, len(raw.Values))
	for k := range raw.Values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if op != "SET" {
			return nil, "", fmt.Errorf(`%s takes "param" or "params"`, op)
		}
		if err := add(k, raw.Values[k], true); err != nil {
			return nil, "", err
		}
	}
	if len(cmd.keys) == 0 {
		return nil, "", errors.New(`the command names no parameter ("param", "params" or "values")`)
	}
	if len(cmd.keys) > 5 {
		return nil, "", fmt.Errorf("%d keys in one command; a device need take only 5 (clause 4.3), so send several commands", len(cmd.keys))
	}
	seen := map[string]bool{}
	for _, k := range cmd.keys {
		if seen[k] {
			return nil, "", fmt.Errorf("%s appears twice", k)
		}
		seen[k] = true
	}
	return cmd, "", nil
}

func sourceNames(s string) string {
	var out []string
	for _, r := range s {
		switch r {
		case 'P':
			out = append(out, "the PVT server")
		case 'E':
			out = append(out, "the emergency server")
		case 'C':
			out = append(out, "the control centre number")
		}
	}
	return strings.Join(out, " or ")
}

// frame builds the command line. Its XOR checksum covers the characters
// between '$' and '*', or with the '$' when withDollar (the form the
// device's own packets use: item 18 does not say where it starts, F-179).
func (o *otaCommand) frame(imei, password string, withDollar bool) string {
	var items []string
	for i, k := range o.keys {
		if o.op == "SET" {
			items = append(items, k+":"+o.values[i])
		} else {
			items = append(items, k)
		}
	}
	body := imei + "," + password + "," + o.op + "," + strings.Join(items, ",")
	sum := xorHex(body)
	if withDollar {
		sum = xorHex("$" + body)
	}
	return "$" + body + "*" + sum + "\r\n"
}

// xorForm reports which XOR checksum form a packet used: with the '$'
// (true) or without; ok is false when its checksum is not two hex digits
// that match either form.
func xorForm(text, sum string) (withDollar, ok bool) {
	if len(sum) != 2 || !strings.HasPrefix(text, "$") {
		return false, false
	}
	without := xorHex(text[1:])
	with := xorHex(text)
	switch {
	case strings.EqualFold(without, sum):
		return false, true
	case strings.EqualFold(with, sum):
		return true, true
	}
	return false, false
}

// xorHex is the checksum of item 18 over s.
func xorHex(s string) string {
	var x byte
	for i := 0; i < len(s); i++ {
		x ^= s[i]
	}
	return fmt.Sprintf("%02X", x)
}

// OTAResponse is a parsed OTA response field.
type OTAResponse struct {
	Source string
	Op     string
	Items  []OTAItem
}

// OTAItem is one executed key.
type OTAItem struct {
	ID, Value string
	OK        bool
}

// ParseOTAResponse reads "(SOURCE|OP|id:value:status|…)"; "()" and
// anything else is not a response. The value is what lies between the
// first and the last ':' of an item, since values (a domain and port) may
// hold colons; empty items (a trailing '|', as in some of the text's
// examples) are skipped (F-182).
func ParseOTAResponse(s string) (*OTAResponse, bool) {
	s = strings.TrimSpace(s)
	if len(s) < 3 || s[0] != '(' || s[len(s)-1] != ')' {
		return nil, false
	}
	parts := strings.Split(s[1:len(s)-1], "|")
	if len(parts) < 3 {
		return nil, false
	}
	r := &OTAResponse{Source: strings.TrimSpace(parts[0]), Op: strings.ToUpper(strings.TrimSpace(parts[1]))}
	if r.Op != "SET" && r.Op != "GET" && r.Op != "CLR" {
		return nil, false
	}
	for _, it := range parts[2:] {
		it = strings.TrimSpace(it)
		if it == "" {
			continue
		}
		first, last := strings.IndexByte(it, ':'), strings.LastIndexByte(it, ':')
		if first < 0 || last == first {
			return nil, false
		}
		st := it[last+1:]
		if st != "0" && st != "1" {
			return nil, false
		}
		r.Items = append(r.Items, OTAItem{ID: it[:first], Value: it[first+1 : last], OK: st == "1"})
	}
	if len(r.Items) == 0 {
		return nil, false
	}
	return r, true
}

// details are the command result's fields for a response.
func (r *OTAResponse) details() map[string]any {
	vals, st := map[string]any{}, map[string]any{}
	for _, it := range r.Items {
		vals[it.ID] = it.Value
		st[it.ID] = it.OK
	}
	return map[string]any{"source": r.Source, "op": r.Op, "values": vals, "done": st}
}
