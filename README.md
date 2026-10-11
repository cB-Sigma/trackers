# trackers

Decoders, command framing and answer correlation for GPS vehicle tracker protocols and AIS-140, in pure Go.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/trackers.svg)](https://pkg.go.dev/github.com/cB-Sigma/trackers) [![test](https://github.com/cB-Sigma/trackers/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/trackers/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.24.0-00ADD8.svg)](go.mod)

The protocols are GT06/Concox, Teltonika, TK103/GPS103, Queclink @Track,
Meitrack, Ruptela, JT/T 808, H02, OsmAnd (phone apps and Traccar
forwarding) and AIS-140, India's standard for vehicle location tracking
devices. One codec per connection reads frames, says what to answer, and
frames commands. No cgo, no dependencies beyond the standard library.
It was written for SigmaM2M, a oneM2M platform, and has no dependency on
it.

## Features

| Protocol | Decoded | Commands | Not read |
|---|---|---|---|
| GT06 | login, 0x12/0x22 location (history flag), 0x13 status, 0x16/0x26 alarms, 0x8A time, 0x94 information, LBS 0x18/0x24/0x28/0x2C/0x2E, WiFi 0x17/0x69, answers 0x15/0x21 | 0x80 text, named; correlated by server flag | other protocol numbers (passed over with a warning) |
| Teltonika | codecs 8, 8E, 16 over TCP and UDP; codec 13 messages; IO elements to status and alerts | codec 12, or 14 (IMEI-addressed); named, interval only by profile template | other codecs (passed over with a warning) |
| TK103 | login, heartbeat, reports with keywords | text, named (no reboot); the protocol has no answers | other frames (passed over) |
| Queclink | +RESP/+BUFF ASCII reports, +ACK heartbeats and acknowledgements | AT+GT commands with the password, named; correlated by serial | the HEX (binary) format |
| Meitrack | AAA reports, CCE batches, command answers | text, named (no reboot by default); correlated by data identifier | CCC batches (no public description), pictures (D00) |
| Ruptela | records (1, 68), identification (15, 18), heartbeat, diagnostic codes, text and set-IO answers | SMS commands over GPRS with the password, set IO, named (interval only by profile template); with commandIds correlated | other commands (passed over) |
| JT808 | JT/T 808-2013 and 2019 headers, registration, authentication, heartbeat, logout, location, batch and blind-area uploads, subpackages joined, Jimi 0x6006/0x0900 text answers | 0x8300 or 0x8900 text, 0x8500 engine control, 0x8201 locate, 0x8105 reboot, 0x8103 interval; correlated | encrypted bodies (answered "not supported"); other messages (acknowledged and passed over) |
| H02 | V1 and related positions, VP1, BC history, ALRM, V3/NBR cells, LINK, heartbeats, V4 answers, 32- and 45-byte binary records | S20, CR, CQ, XT and text, named | other types (passed over) |
| OsmAnd | query and form requests, older Traccar Client JSON, Traccar forwarding JSON | none (the protocol has no command channel) | |
| AIS-140 | LGN, PVT, HLM, EPB, emergency SMS, ACTVR/HCHKR by the Amendment 3 sequence or by anchors; vendor layouts by profile; XOR and CRC-32 checksums | Table 4D SET/GET/CLR with the password and XOR checksum, the older text form, named (reboot, interval); OTA responses correlated by operation and keys; HCHK/ACTV named as SMS requests | sending SMS (a server's job) |

Commands are the protocol's text (`{"text": "WHERE#"}`), a protocol's own
form (`{"op": "GET", "param": "001"}` on AIS-140), or a named command that
means the same everywhere: `engineStop`, `engineResume`, `locate`,
`reboot`, `interval` (`track.Named`). A codec that is a `track.Correlator`
says which answer belongs to which command.

Not here: the TCP/UDP/TLS listener, sessions, device lists, command
queues, SMS, storage and the mapping of positions to anything else. Those
are the server's.

## Choosing a tracker protocol library

Compared from each project's source or documentation at the versions
named, in October 2026. Check the projects themselves before relying on
a row.

| | this module | Traccar v6.16.0 (Java) | alim-zanibekov/teltonika (2024 commit) | filipkroca/teltonikaparser v1.0.0 | cuteLittleDevil/go-jt808 protocol v1.18.0 |
|---|---|---|---|---|---|
| What it is | Go library: decode, answer, frame commands | a complete tracking server with web interface, storage and notifications | Go library | Go library | Go library and server framework |
| Licence | Apache-2.0 | Apache-2.0 | MIT | BSD-3-Clause | MIT |
| Protocols | 10 plus AIS-140 | more than 250 | Teltonika | Teltonika | JT/T 808 and JT/T 1078 |
| Teltonika | codecs 8, 8E, 16 over TCP and UDP; 12, 13, 14 | yes | codecs 8, 8E, 16, 12, 13, 14, 15 over TCP and UDP; IO element names | codecs 8 and 8E over UDP only; 12 | no |
| GT06/Concox, TK103, H02, Queclink, Meitrack, Ruptela, OsmAnd | yes | yes | no | no | no |
| JT/T 808 | 2013 and 2019, no encrypted bodies | yes | no | no | 2011, 2013 and 2019, sub-packages, active-safety extensions, JT/T 1078 video signalling |
| AIS-140 (India) | LGN, PVT, HLM, EPB, health and activation; Table 4D OTA commands correlated with their answers | packets of several vendors (its "its" protocol); engine stop and resume | no | no | no |
| Same named commands across protocols | yes (`engineStop`, `locate`, `reboot`, `interval`) | yes | no | no | no |
| Runs inside a Go program | yes, no dependencies | no, a separate Java service | yes | yes | yes |

The other Go GT06 repositories found (hainn191297/gt06,
track-any-device/server-gt06) carry no licence, so they cannot be reused.

Pick this module when a Go server must take several tracker brands, or
AIS-140 devices for Indian permits, and keep the listener, storage and
commands its own. Pick Traccar when you want a ready tracking server
rather than a library, or a protocol not listed here. Pick
alim-zanibekov/teltonika for a Teltonika-only fleet that needs codec 15
or IO element names, and go-jt808 for Chinese JT/T 808 fleets with
JT/T 1078 video or active-safety terminals.

## Install

```
go get github.com/cB-Sigma/trackers@latest
```

Requires Go 1.24.0 or later.

## Quick start

Decode a GT06 login and frame a named command for the device (from
`gt06.Example`):

```go
newCodec, err := gt06.NewCodec(nil) // the default profile
if err != nil {
	panic(err)
}
c := newCodec() // one per connection
login, _ := hex.DecodeString("78780D01012345678901234500018CDD0D0A")
m, err := c.Decode(bufio.NewReader(bytes.NewReader(login)))
if err != nil {
	panic(err)
}
fmt.Println(m.IMEI, m.Login, hex.EncodeToString(m.Reply))
frame, answers, err := c.Command(m.IMEI, map[string]any{"action": "locate"}, 7)
fmt.Println(hex.EncodeToString(frame), answers, err)
// Output:
// 123456789012345 true 787805010001d9dc0d0a
// 787812800a000000075748455245230002000766ab0d0a true <nil>
```

On a connection, a server calls `Decode` in a loop, skips
`track.ErrSkip`, writes `m.Reply` back, and reads `m.Records` (fix,
alerts, status, cells and WiFi).

Other runnable examples: `track.ExampleNamedText`, `ais140.Example` (a
Table 4D command and its correlation) and `ais140.ExampleParseDeviceID`.

## Documentation

Reference: https://pkg.go.dev/github.com/cB-Sigma/trackers

| Package | What it does |
|---|---|
| `track` | What every protocol shares: `Fix`, `Alert`, `Record`, `Message`, `Network` (cells, WiFi); the `Codec` interface and the optional `Correlator`, `DatagramCodec`, `DatagramCommander`, `PasswordCommander`, `SMSRequester`; named commands; alert types and severities; CRC-16/X-25 and CRC-16/ARC |
| `gt06` | GT06 / Concox binary frames; 0x80 commands correlated by server flag |
| `teltonika` | Teltonika AVL over TCP and UDP: codecs 8, 8E and 16; codec 12, 13 and 14 commands and answers |
| `tk103` | TK103 / Coban (GPS103) text: login, heartbeat, reports and alarm keywords; commands |
| `queclink` | Queclink @Track ASCII reports, heartbeats, acknowledgements; AT+GT commands with the device password, correlated by serial |
| `meitrack` | Meitrack GPRS: AAA reports, CCE batches; commands correlated by data identifier |
| `ruptela` | Ruptela records and extended records, identification, heartbeat; SMS commands over GPRS with the device password, set IO |
| `jt808` | JT/T 808-2013 and 2019 (and Jimi variants); 0x8300, 0x8201 and 0x8500 commands |
| `h02` | H02 (Sinotrack and others) text and binary; S20, CR, CQ, XT commands |
| `osmand` | The OsmAnd HTTP protocol of phone apps, their JSON bodies, and a Traccar server's position forwarding |
| `ais140` | AIS-140 with Amendments 1 to 3: LGN, PVT, HLM, EPB packets; XOR and CRC-32 checksums; Table 4D OTA commands and responses; the unique device ID; health check and activation SMS requests |

## Testing

```
go vet ./...
go test -race ./...
```

Tests carry `// Covers: SIG-...` comments. These are requirement IDs of
the SigmaM2M project's compliance report and have no meaning outside it.

## Interop tested against

The tests decode the manufacturers' published sample frames and, where
credited in NOTICE, device packets published in Traccar's decoder tests
(packets real devices sent). The AIS-140 tests use packets of our own in
the standard's layouts, plus the Traccar packets of several
manufacturers. The simulators (see below) are written from the same
documents as the decoders, so testing against them is not independent.
No real device of these protocols has been tested against this code yet:
Queclink, Meitrack, Ruptela, JT808, H02 and OsmAnd are untested with real
devices, and the named-command texts of GT06, Teltonika and TK103 need a
real-device check.

## Related repositories

- [trackers-sim](https://github.com/cB-Sigma/trackers-sim): a simulated
  tracker of every protocol here, as Go packages for tests and as a
  command (`trackersim`) to run against a server.

## Status

v0.x. The API may change before v1.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## Licence

Apache-2.0 (see [LICENSE](LICENSE)). Copyright 2026 Abhinav Gautam.
[NOTICE](NOTICE) credits the third-party test data and names the
trademarks used. [PROVENANCE.md](PROVENANCE.md) says how the code was
written and where the test data came from.
