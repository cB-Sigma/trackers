// Copyright 2026 Abhinav Gautam
// SPDX-License-Identifier: Apache-2.0

package tk103_test

import (
	"bufio"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/cB-Sigma/trackers/tk103"
	"github.com/cB-Sigma/trackers/track"
)

const imei = "359586015829802"

// The login, heartbeat and tracker frames from the GPS103 (Coban) protocol
// document decode with their answers, fix and time; a keyword frame
// carries its alert; an unknown frame is skipped with a warning.
func TestDecodeFrames(t *testing.T) {
	nc, err := tk103.NewCodec(nil)
	if err != nil {
		t.Fatal(err)
	}
	c := nc()
	br := bufio.NewReader(strings.NewReader("##,imei:359586015829802,A;" + "359586015829802;" +
		"imei:359586015829802,tracker,0809231929,13554900601,F,112909.397,A,2234.4669,N,11354.3287,E,0.11,;" +
		"imei:359586015829802,help me,0809231929,13554900601,F,112909.397,A,2234.4669,N,11354.3287,E,0.11,;" +
		"hello,vendor,extension;"))
	m, err := c.Decode(br)
	if err != nil || !m.Login || m.IMEI != imei || string(m.Reply) != "LOAD" {
		t.Fatalf("login %+v %v", m, err)
	}
	m, err = c.Decode(br)
	if err != nil || m.IMEI != imei || string(m.Reply) != "ON" {
		t.Fatalf("heartbeat %+v %v", m, err)
	}
	m, err = c.Decode(br)
	if err != nil || len(m.Records) != 1 || m.Records[0].Fix == nil {
		t.Fatalf("tracker %+v %v", m, err)
	}
	f := m.Records[0].Fix
	// 22°34.4669' N, 113°54.3287' E; 0.11 knots; 2008-09-23 11:29:09 UTC.
	if !f.Valid || f.Lat < 22.57444 || f.Lat > 22.57445 || f.Lon < 113.90547 || f.Lon > 113.90548 ||
		*f.Speed != 0.2 || !f.Time.Equal(time.Date(2008, 9, 23, 11, 29, 9, 0, time.UTC)) {
		t.Fatalf("fix %+v", f)
	}
	m, err = c.Decode(br)
	if err != nil || len(m.Records) != 1 || len(m.Records[0].Alerts) != 1 || m.Records[0].Alerts[0].Type != "emergency" {
		t.Fatalf("help me %+v %v", m, err)
	}
	var sk *track.Skip
	if _, err := c.Decode(br); !errors.As(err, &sk) || sk.Code != "unknownMessage" {
		t.Fatalf("unknown frame: %v", err)
	}
}
