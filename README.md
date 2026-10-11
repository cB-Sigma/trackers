# trackers

Decoders, command framing and answer correlation for GPS vehicle tracker protocols and AIS-140, in pure Go.

[![Go Reference](https://pkg.go.dev/badge/github.com/cB-Sigma/trackers.svg)](https://pkg.go.dev/github.com/cB-Sigma/trackers) [![test](https://github.com/cB-Sigma/trackers/actions/workflows/test.yml/badge.svg)](https://github.com/cB-Sigma/trackers/actions/workflows/test.yml) [![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue.svg)](LICENSE) [![Go](https://img.shields.io/badge/go-1.24.0-00ADD8.svg)](go.mod)

The protocols are GT06/Concox, Teltonika, TK103/GPS103, Queclink @Track
(ASCII and HEX), Meitrack, Ruptela, JT/T 808 (with active safety and
JT/T 1078 signalling), H02, OsmAnd (phone apps and Traccar forwarding),
Wialon IPS, Galileosky, Suntech, CalAmp LM Direct, ATrack, Eelink, 3G
watches (SeTracker) and AIS-140, India's standard for vehicle location
tracking devices. One codec per connection reads frames, says what to
answer, and frames commands. No cgo, no dependencies beyond the standard
library. It was written for SigmaM2M, a oneM2M platform, and has no
dependency on it.

## Features

| Protocol | Decoded | Commands | Not read |
|---|---|---|---|
| GT06 | login; location 0x10/0x12/0x22/0xA0 (history flag); status 0x13, heartbeat 0x23; alarms 0x16/0x26/0x27/0xA3/0xA4 with the cell, cell alarms 0x19/0xA5; cells and WiFi 0x18/0x24/0x28/0x2C/0x2E/0xA1/0xA2/0x17/0x69; address requests 0x2A/0x17/0xA7 (`AddressReply` builds 0x97); time 0x8A; information 0x94; external data 0x9B; 0x7979 0x32/0x33; answers 0x15/0x21 | 0x80 text, named; correlated by server flag | 0x98, 0x9C and single-vendor numbers no public source describes (passed over with a warning) |
| Teltonika | codecs 8, 8E, 16 and GH codec 7 over TCP and UDP; codec 13 and 15 device messages; codec 12/14 answers; IO elements to status and alerts, and by name from the FMB AVL ID list with `ioNames` | codec 12, or 14 (IMEI-addressed); named, interval as FMB `setparam` | codecs 12/13/15 over UDP (no published layout); other codecs (passed over with a warning) |
| TK103 | login, heartbeat, reports with keywords | text, named (reboot only by profile template: no public GPRS reboot command); the protocol has no answers | other frames (passed over) |
| Queclink | +RESP/+BUFF ASCII and HEX (+RSP/+BSP, +EVT/+BVT, +INF/+BNF) reports, +ACK/+HBD heartbeats and acknowledgements in both formats, the 0x2B00 record frame | AT+GT commands with the password, named; correlated by serial (ASCII or HEX acknowledgements) | crash data (+CRD), +DAT and +CAN frames (passed over); CAN data and GTERI 1-wire items inside HEX reports |
| Meitrack | AAA reports, CCE and CCC batches (CCC confirmed with its count), D00 pictures reassembled (the next eight asked for automatically; event 39 can fetch at once), D01 picture list, command answers | text, named (no reboot by default); correlated by data identifier | CCC header bytes other than the record length |
| Ruptela | records (1, 68), identification (15, 18), heartbeat, trouble codes per code (9), text answers (2, 3, 4, 7), set-IO answer, transparent channel (14), weighing (32), Garmin status (30), SD-card log records (34), camera files (37) | SMS commands over GPRS with the password, set IO, version, connection, odometer, file list and fetch; named (interval only by profile template: no documented period parameter); with commandIds correlated | beacons (38) and accident data (35) acknowledged only; tachograph, smart card, Garmin FMI, fuel-level channel |
| JT808 | JT/T 808-2011 registration, 2013 and 2019 headers, registration, authentication, heartbeat, logout, location, batch and blind-area uploads, subpackages joined; RSA-encrypted bodies (platform key in the profile, 0x0A00/0x8A00 exchange); active safety items 0x64 ADAS, 0x65 DSM, 0x66 TPMS, 0x67 BSD as alerts; 0x1210/0x1211/0x1212 attachment messages answered; JT/T 1078 0x1003 and 0x1205 answers; Jimi 0x6006/0x0900 text answers | 0x8300 or 0x8900 text, 0x8500 engine control, 0x8201 locate, 0x8105 reboot, 0x8103 interval, 0x9208 attachment upload, JT/T 1078 0x9003/0x9101/0x9102/0x9201/0x9202/0x9205, 0x8A00 key; commands encrypted to terminals whose key is known; correlated | attachment file data (passed over, not stored); JT/T 1078 media streams; non-RSA encryption (answered "not supported"); other messages (acknowledged and passed over) |
| H02 | V1 and related positions, VP1, BC history, ALRM, V3/NBR cells, LINK, heartbeats, V4 and SMS answers, 32- and 45-byte binary records, Cantrack Y-model records | S20, CR, CQ, XT and text, named | the 45-byte record's last 13 bytes and the 'X' record (no public description) |
| OsmAnd | query and form requests, older Traccar Client JSON, Traccar forwarding JSON | none (the protocol has no command channel) | |
| Wialon IPS | 1.1 and 2.0: login with password, short and extended data with typed parameters (SOS alert, cells, driver text), black box, ping, driver messages, pictures, tachograph files, compressed packets; UDP form; CRC checked | custom text, driver message, picture and DDD requests, firmware and configuration upload; named only by profile template (the protocol defines none) | answers name no command (no correlation) |
| Galileosky | head and main packets with several records; the tag table (coordinates, speed and course, status bits as alerts, voltages, inputs and outputs, fuel and temperature sensors, CAN registers, iButton, user data, extended tags); command answers; pictures | command packets (tags 0xE0/0xE1) correlated by number; named (interval only by profile template) | compressed packets (0x08), Garmin FMI, XTEA encryption, Iridium form; tags of unknown length (profile `tagLengths`) |
| Suntech | older protocol (SA200, ST3xx, ST500, ST600) and Universal STT/EMG/EVT/ALT/UEX reports, ALV keep-alives, CMD;Res/RES answers; Universal binary 0x81/0x82 | text, named (interval only by profile template); correlated by command name | ST41x and ST9xx layouts, compressed binary (0x02), BLE/BSA/HTE/CRR (passed over with a warning) |
| CalAmp LMU | LM Direct over UDP: options header (mobile ID), event (2), locate (8), mini event (10), user data (4), unit ACK/NAK (1); acknowledgements | user data text, raw hex message; correlated by sequence; named only by profile template | TCP, ID report contents (3), other message types (acknowledged and passed over), options extension |
| ATrack | binary and ASCII @P positions (CRC-16/ARC; custom fields by %CI or profile: voltages, satellites, cell, VIN, ICCID, OBD/J1939 raw), keep-alive, $OK/$ERROR/$INFO answers | AT$ text with a sequence tag (correlated), command password; named | pictures @R (acknowledged, passed over); custom fields of unknown size |
| Eelink | 1.x login, GPS, heartbeat, alarm, state, SMS, OBD; 2.0 login, location (cells, WiFi, LTE, battery, mileage, sensors), warning, report, message; instruction answers 0x80; UDP datagrams | 0x80 instruction with the sequence as UID (correlated), TCP and UDP; named | 2.0 OBD, pedometer and parameter packages 0x17 to 0x1B (answered, passed over) |
| Watch (3G/SeTracker) | LK, UD/UD2/UD3/UD_LTE/UD_WCDMA/WT/WG/WAD positions with cells and WiFi, AL alarms, INIT, TKQ, health (pulse, blood pressure, temperature, oxygen), command answers by keyword | `[vendor*id*len*text]` with the device's vendor and index form (correlated by keyword); named locate, reboot, interval; SOS numbers | voice and pictures (TK, img, JXTK; passed over) |
| AIS-140 | LGN, PVT, HLM, EPB, emergency SMS, ACTVR/HCHKR by the Amendment 3 sequence or by anchors; RLP and CTPL layouts (frame number, odometer, accelerations, tilts) by packet or profile `vendor`/`tail`; XOR and CRC-32 checksums | Table 4D SET/GET/CLR with the password and XOR checksum, the older text form, named (reboot, interval); OTA responses correlated by operation and keys; HCHK/ACTV named as SMS requests | sending SMS (a server's job) |

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
| Protocols | 17 plus AIS-140 | more than 250 | Teltonika | Teltonika | JT/T 808 and JT/T 1078 |
| Teltonika | codecs 8, 8E, 16 and GH 7 over TCP and UDP; 12, 13, 14, 15; IO element names | yes | codecs 8, 8E, 16, 12, 13, 14, 15 over TCP and UDP; IO element names | codecs 8 and 8E over UDP only; 12 | no |
| GT06/Concox, TK103, H02, Queclink, Meitrack, Ruptela, OsmAnd, Wialon IPS, Galileosky, Suntech, CalAmp, ATrack, Eelink, 3G watches | yes | yes | no | no | no |
| JT/T 808 | 2011, 2013 and 2019, sub-packages, RSA bodies, active-safety items and attachment messages, JT/T 1078 signalling (no media) | yes | no | no | 2011, 2013 and 2019, sub-packages, active-safety extensions, JT/T 1078 video signalling |
| AIS-140 (India) | LGN, PVT, HLM, EPB, health and activation; RLP and CTPL layouts; Table 4D OTA commands correlated with their answers | packets of several vendors (its "its" protocol); engine stop and resume texts in its encoder, which 6.16.0 cannot send (see Interop) | no | no | no |
| Checked against an independent implementation | Traccar 6.16.0 in Docker: positions, alarms and command frames (see Interop) | | | | |
| Same named commands across protocols | yes (`engineStop`, `locate`, `reboot`, `interval`) | yes | no | no | no |
| Runs inside a Go program | yes, no dependencies | no, a separate Java service | yes | yes | yes |

The other Go GT06 repositories found (hainn191297/gt06,
track-any-device/server-gt06) carry no licence, so they cannot be reused.

Pick this module when a Go server must take several tracker brands, or
AIS-140 devices for Indian permits, and keep the listener, storage and
commands its own. Pick Traccar when you want a ready tracking server
rather than a library, or a protocol not listed here. Pick
alim-zanibekov/teltonika when you only need Teltonika and want its
smaller API, and go-jt808 when you want a ready JT/T 808 server framework
(sessions and handlers included) rather than a codec, or JT/T 1078 media.

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
| `teltonika` | Teltonika AVL over TCP and UDP: codecs 8, 8E, 16 and GH 7; codec 12, 13, 14 and 15 commands, answers and messages; the FMB IO element table (`IOName`, `IOElements`) |
| `tk103` | TK103 / Coban (GPS103) text: login, heartbeat, reports and alarm keywords; commands |
| `queclink` | Queclink @Track ASCII and HEX reports, heartbeats, acknowledgements; AT+GT commands with the device password, correlated by serial |
| `meitrack` | Meitrack GPRS: AAA reports, CCE and CCC batches, D00 pictures and the D01 list; commands correlated by data identifier |
| `ruptela` | Ruptela records and extended records, identification, heartbeat, trouble codes, transparent channel, weighing, SD-card log, camera files; SMS commands over GPRS with the device password, set IO and binary commands |
| `jt808` | JT/T 808-2011, 2013 and 2019 (and Jimi variants); RSA bodies; active-safety items and attachment messages; JT/T 1078 signalling; text, locate, vehicle control, reboot and interval commands |
| `h02` | H02 (Sinotrack and others) text and binary, Cantrack Y-model records; S20, CR, CQ, XT commands |
| `osmand` | The OsmAnd HTTP protocol of phone apps, their JSON bodies, and a Traccar server's position forwarding |
| `wialon` | Wialon IPS 1.1 and 2.0 over TCP and UDP, with CRC and compressed packets; custom, message, picture, DDD and upload commands |
| `galileosky` | Galileosky tag protocol: multi-record packets, CRC-16/MODBUS confirmation, the tag table, pictures; command packets correlated by number |
| `suntech` | Suntech older and Universal text protocols and Universal binary; commands correlated with their answers |
| `calamp` | CalAmp LM Direct over UDP: event, locate, mini event, user data and ACK messages; server acknowledgements; user data commands correlated by sequence |
| `atrack` | ATrack binary and ASCII positions with custom fields, keep-alive; tagged AT$ commands with the command password |
| `eelink` | Eelink protocol 1.x and 2.0 packages over TCP and UDP; 0x80 instructions correlated by UID |
| `watch` | The 3G/SeTracker bracket protocol of kids' watches and small trackers: positions, alarms, health readings; commands correlated by keyword |
| `ais140` | AIS-140 with Amendments 1 to 3: LGN, PVT, HLM, EPB packets; XOR and CRC-32 checksums; Table 4D OTA commands and responses; the unique device ID; health check and activation SMS requests |

## Testing

```
go vet ./...
go test -race ./...
```

Tests carry `// Covers: SIG-...` comments. These are requirement IDs of
the SigmaM2M project's compliance report and have no meaning outside it.

## Interop tested against

| Peer | What was checked | Result |
|---|---|---|
| Traccar 6.16.0 (traccar/traccar Docker image), positions | the simulators of [trackers-sim](https://github.com/cB-Sigma/trackers-sim) send three positions in both hemispheres for every protocol (TCP; also UDP for Teltonika, H02 and CalAmp; Wialon 1.1 and 2.0, ATrack binary and ASCII, Suntech Universal and ST300), read back through Traccar's REST API | every protocol's positions arrive with the coordinates, speed and course sent |
| Traccar 6.16.0, alarms | an SOS from GT06, TK103, Queclink, Meitrack, JT808, H02, OsmAnd, AIS-140 and Suntech | each arrives as an `sos` alarm event |
| Traccar 6.16.0, command encoders | each command Traccar can send for a protocol here, captured on the wire and compared with our frame for the same command in the same session (framing and checksums checked, serials and times left out) | the same for Teltonika, Queclink, Meitrack, Suntech, Eelink, Watch, Galileosky, H02 engine commands and JT808 locate; the differences are below |
| Traccar decoder tests | device packets real devices sent (credited in NOTICE) | decoded in the unit tests, every protocol |

Where our default command differs from Traccar's, and why:

| Protocol | Command | Traccar | Ours (default) | Traccar's form with our profile |
|---|---|---|---|---|
| GT06 | engine stop/resume | `Relay,1#`, no language bytes | `RELAY,1#` (GT06 v1.8 command list) with the language bytes | `commandLanguage: false` and `namedCommands` |
| TK103 | all | no terminator | `;` terminator, as the GPS103 document shows | `commandTerminator: ""` |
| Ruptela | engine stop | `immobilizer 10` | `immobilizer 5` | `namedCommands` |
| H02 | interval | `S71,<time>,22,<s>` | `XT,<s>` (HuaSunTeK document) | `namedCommands: {interval: "S71,22,{seconds}"}` |
| JT808 | reboot, interval | vendor message 0x0310 | the standard's 0x8105 (reset) and 0x8103 (parameter 0x0029) | none (vendor message) |
| JT808 | engine stop/resume | 0x8105 with vendor word 0xF0/0xF1 | the standard's 0x8500 vehicle control | none |
| ATrack | text | no tag | sequence tag the device echoes, for correlation | `commandTag: false` |
| Wialon IPS | reboot | `reboot` | none (the protocol defines no commands) | `namedCommands` |
| AIS-140 | engine stop/resume | `@SET#RLP,OP1,` / `@CLR#RLP,OP1,` (one vendor) | none (Table 4D has no engine command) | `namedCommands` |

Traccar 6.16.0 itself cannot send AIS-140 ("its") commands: its encoder
returns text that its pipeline cannot write, so the API refuses every
command; the comparison uses the encoder's text from its source at tag
v6.16.0. Traccar answers Wialon IPS 2.0 short data with `#AD#` where the
protocol document gives `#ASD#`; our codec answers `#ASD#`.

The tests live in trackers-sim's `interop` module and run with
`SIGMA_TRACKERS_INTEROP=1` and Docker. The simulators are written from
the same documents as the decoders, so the Traccar check is the
independent one. No real device of these protocols has been tested
against this code yet; the named-command texts, the Wialon 1.1 answer
texts, Galileosky output polarity and the protocols read only from
Traccar's decoders (Suntech, CalAmp, some GT06 and Queclink frames) need
a real-device check.

## Not yet

| Item | Why |
|---|---|
| A check of every protocol with real devices | needs hardware |
| JT808 active-safety and JT/T 1078 layouts against the official T/JSATL12 and JT/T 1078 texts | paid or not freely published; checked against public implementations and Traccar's vector |
| CalAmp HDOP and fix-status bits, unit request (type 7) actions, ID report, TCP framing | need CalAmp's LM Direct Reference Guide, which is not public |
| Suntech compressed binary, ST41x/ST9xx layouts, an interval command | no public Suntech document; the speed unit of the compressed form is not confirmed by any source |
| Ruptela interval, beacons (38) and accident data (35) | no documented period parameter; the public copy of the protocol lacks the two layouts |
| TK103 reboot by default | no public GPRS reboot command (a profile template sets one) |
| Teltonika codecs 12/13/15 over UDP | Teltonika publishes no UDP layout for them |
| Galileosky compressed packets, Garmin FMI, XTEA, Iridium | described only by Traccar's code without test vectors, or not at all |
| Queclink CAN data and GTERI extras in HEX reports, GL300 report type 100 | not in the GV300N document |
| GT06 0x98, 0x9C | no public description |
| JT/T 1078 media, attachment file storage, sending SMS | a server's job, not a codec's |

## Related repositories

- [trackers-sim](https://github.com/cB-Sigma/trackers-sim): a simulated
  tracker of every protocol here, as Go packages for tests and as a
  command (`trackersim`) to run against a server.

## Status

v0.2.0 (see [CHANGELOG.md](CHANGELOG.md)). It keeps the v0.1.0 Go API and
adds to it; the few behaviour changes are listed in the changelog. The API
may change before v1.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Security

See [SECURITY.md](SECURITY.md).

## Licence

Apache-2.0 (see [LICENSE](LICENSE)). Copyright 2026 Abhinav Gautam.
[NOTICE](NOTICE) credits the third-party test data and names the
trademarks used. [PROVENANCE.md](PROVENANCE.md) says how the code was
written and where the test data came from.
