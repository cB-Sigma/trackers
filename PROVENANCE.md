# Provenance

## How the code was written

Written for SigmaM2M, a oneM2M platform, in Go, from the manufacturers'
published protocol documents and, for AIS-140, the ARAI standard with its
amendments. No code was ported or copied from another implementation.
Traccar (Apache-2.0), the open-source Java tracking server, was used in
two ways only: device packets published in its decoder tests are test
vectors (protocol facts: bytes a real device sent), and, for H02, JT808
and OsmAnd, its decoders were read for how devices behave where the
documents are silent or wrong. Facts are not code: frame layouts, message
IDs, field orders, checksum algorithms and command words are what every
implementation must use, and the code around them is our own design (the
track types, one codec per connection, the named commands, the
correlation of command answers, our own error handling and warnings). No
specification or manual text is reproduced; comments describe layouts in
our own words with clause, table or section numbers.

The protocol packages were first written as the codecs of SigmaM2M's
tracker connectors. GT06, Teltonika, TK103 and AIS-140 date from
2026-09-27; Queclink, Meitrack, Ruptela, JT808, H02 and OsmAnd were added
on 2026-10-05/06, after a search for the public documents listed below.
The shared `track` package was cut out of SigmaM2M's tracker framework on
2026-10-06, when the packages became this module. The simulators are in
a separate module, trackers-sim.

## Sources

| Package | Followed | Traccar, read for facts only (no code taken) |
|---|---|---|
| `track` | none (our own types; CRC-16/X-25 and CRC-16/ARC are the catalogued CRC parameters) | none |
| `gt06` | The Concox GT06 protocol tables (login 0x01, location 0x12 and 0x22, status 0x13, alarms 0x16 and 0x26, time 0x8A, information 0x94, commands 0x80, answers 0x15 and 0x21; LBS 0x18, 0x24, 0x28, 0x2C, 0x2E; WiFi 0x17, 0x69); command texts from the GT06 protocol v1.8 command list and the GT06N user manual | Test vectors only: frames quoted in Traccar's GT06 decoder tests (gt06_test.go, lbs_test.go); the LBS and WiFi layouts in lbs.go were checked against them |
| `teltonika` | Teltonika's public protocol description: codecs 8, 8E, 16, 12, 13 and 14, the TCP and UDP framing and acknowledgements; the FMB SMS/GPRS command list (wiki.teltonika-gps.com) for the named commands | none |
| `tk103` | The GPS103 (Coban) protocol document (login, heartbeat, report frames and keywords); the Coban GPRS command letters | none (one profile comment notes that Traccar sends commands without the terminator) |
| `queclink` | Queclink GV300N @Track Air Interface Protocol V3.01 (TRACGV300NAN001); GV300 @Track Air Interface Protocol V2.40; GV350M V3.11 (a Queclink document hosted at traccar.org/protocol/5004-gl200/). The test frames in decode_test.go are the GV300N V3.01 document's examples | none |
| `meitrack` | MEITRACK GPRS Protocol V1.8 (2016-12-19); T1 & T333 GPRS Protocol V1.4 (2018-12-04); T366/T366G/T366L GPRS Protocol V1.5 (2019-07-02); GPRS (CCE ID) Protocol V1.0 (2025-03-30), all from meitrack.com. The test frames in decode_test.go are those documents' examples (V1.8 sections 3.1, 3.3, 3.17, 3.19, 3.21, 3.35, 3.61, 3.63; T1/T333 V1.4 section 3.64; the CCE ID V1.0 sample) | none |
| `ruptela` | Ruptela "Ruptela Protocol" v1.113 (doc* test packets are its examples); Ruptela "SMS Command List" for 4th and 5th generation devices | Test vectors only: device packets devRecords, devIdent, devGetio, devExt from Traccar's decoder tests |
| `jt808` | JT/T 808-2013, in its published English translation (roadragon.com), clauses and tables cited in the code (4.4.2 escaping; tables 12, 18, 24, 25), and the 2019 header change; Jimi IoT (Concox) VL and JC series behaviour (0x6006 and 0x0900 text answers) | Jt808ProtocolDecoder and Jt808ProtocolEncoder, read for vendor behaviour; test vectors from Jt808ProtocolDecoderTest (decode_test.go) |
| `h02` | HuaSunTeK "GPS Tracker Communication Protocol" V1.0.5 (2017) and Cantrack "CANTRACK PROTOCOL" A/1 (2017), manufacturers' documents hosted at traccar.org/protocol/5013-h02/ | The H02 decoder and encoder, read for NBR, LINK, the binary validity nibble and the S71 interval form; test vectors bDoc, bText, b45 from its decoder tests |
| `osmand` | traccar.org/osmand (the OsmAnd parameters, time forms, knots); traccar.org/configuration-file and traccar.org/forward (forward.url, forward.type json, forward.header) | The OsmAnd decoder, read for behaviour; the Position and Device models for the JSON names a forwarding server sends; Traccar Client SDK (HttpUploader.kt: the form POST, knots, battery) and Traccar Client (main_screen.dart: the SOS alarm); test vectors from OsmAndProtocolDecoderTest and the OsmAnd page |
| `ais140` | AIS-140 (ARAI, October 2016) with Amendment 1 (11 December 2017), Amendment 2 (5 December 2018) and Amendment 3 (04/2026, printed 7 May 2026): the login, data, health, emergency and emergency SMS packet tables (4A(1), 4A(2), 3B, 4C), alert IDs, the OTA commands of Table 4D and their responses, the checksum (item 18), the unique device ID (3.1.1.12), the RFID trailer ID (3.1.1.28), and the activation and health check SMS (Amendment 2, 8.4). An ARAI publication, not redistributed here | Test vectors only: AIS-140 packets of several manufacturers from Traccar's decoder tests (ais140_test.go, fieldVectors) |

## Notes on AIS-140 (F-numbers)

Comments in `ais140` cite F-numbers. F-n refers to an entry in SigmaM2M's
register of specification defects; the substance of each is described
here.

- F-178: the data packet table skips a row number (no row 52), and the
  emergency table skips one too; no field is missing, so the code reads
  the fields in order.
- F-179: the checksum item does not say which characters are XORed (with
  or without the '$'), and the checksums printed in the standard's sample
  packets match neither range. The code accepts either range, and
  ignores checksums unless a profile asks for `xor`.
- F-180: the neighbour cells' signal strength has no unit or range, and
  the samples exceed the serving cell's 0 to 31; neighbour values are
  kept as sent.
- F-182: OTA responses separate ID, value and status with ':' although
  values may contain ':', some examples carry an extra ID before an item,
  and some end with an empty item. The code takes the value between the
  first and last ':' and skips empty items.
- F-183: the emergency SMS date is described as six digits of date, but
  the sample uses an eight-digit date; both are read.
- F-186: the unique device ID is stored with the IMEI but no packet
  carries it, so it is a device setting checked when loaded.

## Test data

- Manufacturers' sample frames: protocol facts from the documents above.
- Traccar test vectors: device packets, used as protocol facts, credited in
  NOTICE. Their checksums were checked independently where the tests say
  so (GT06 CRCs, Ruptela CRCs, JT808 check codes).
- AIS-140: the tests in `ais140/amd3_test.go` use packets of our own built
  to the standard's field layouts (made-up IMEIs 86000000000xxxx, ICCIDs
  starting 8991000, vehicle, positions, times, cells and tag), with
  checksums computed by the routine. They are not the standard's sample
  packets. The OTA response examples there are ours too.
- Everything else (IMEIs, phone numbers, passwords, positions, device IDs)
  is made up, except IMEIs that appear inside the Traccar test vectors.
  Some tests reuse one such public IMEI (861693034634154, from Traccar's
  Apache-2.0 AIS-140 tests) as a demo value.

## Checks

- A search of the code for porting markers ("ported", "adapted from",
  "translated from", "based on") and for Traccar's helper names
  (PatternBuilder, BitUtil, UnitsConverter, DateBuilder) found nothing
  beyond the attribution comments.
- A review for specification prose (2026-10-11) found no copied passages
  and no normative sentences in comments; comments cite clause, table and
  figure numbers in our own words. One four-word phrase of AIS-140 is
  quoted, with attribution, in `ais140/standard.go`.
- Not done: a line-by-line similarity check against Traccar's decoders.
  Both projects are Apache-2.0, so such a check is about crediting
  exactly, not about the licence.
- The licences of Traccar, Traccar Client and the Traccar Client SDK were
  confirmed from their LICENSE files on 2026-10-11 (Apache-2.0).
