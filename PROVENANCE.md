# Provenance

## How the code was written

Written for SigmaM2M, a oneM2M platform, in Go, from the manufacturers'
published protocol documents and, for AIS-140, the ARAI standard with its
amendments. No code was ported or copied from another implementation.
Traccar (Apache-2.0), the open-source Java tracking server, was used in
three ways only: device packets published in its decoder tests are test
vectors (protocol facts: bytes a real device sent); its decoders were
read for facts (frame layouts, field orders, message numbers) where the
documents are silent, wrong or not public, as the Sources table says per
package; and its server, run unchanged in Docker, is the independent peer
of the interop tests (trackers-sim's `interop` module). Facts are not code: frame layouts, message
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
Wialon IPS, Galileosky, Suntech, CalAmp, ATrack, Eelink and Watch were
added for v0.2.0 on 2026-10-11, together with the v0.2.0 additions to the
existing packages.
The shared `track` package was cut out of SigmaM2M's tracker framework on
2026-10-06, when the packages became this module. The simulators are in
a separate module, trackers-sim.

## Sources

| Package | Followed | Traccar, read for facts only (no code taken) |
|---|---|---|
| `track` | none (our own types; CRC-16/X-25 and CRC-16/ARC are the catalogued CRC parameters) | none |
| `gt06` | The Concox GT06 protocol tables (login 0x01, location 0x12 and 0x22, status 0x13, alarms 0x16 and 0x26, time 0x8A, information 0x94, commands 0x80, answers 0x15 and 0x21; LBS 0x18, 0x24, 0x28, 0x2C, 0x2E; WiFi 0x17, 0x69); command texts from the GT06 protocol v1.8 command list and the GT06N user manual; Concox "GPS Tracker Communication Protocol" (GK310) V1.0.3, https://www.traccar.org/protocol/5023-gt06/GK310%20Communication%20Protocol.docx (0x23, 0x27, 0x19, 0x2A, 0x17, 0x97, 0xA0 to 0xA7, the alarm table, 0x94 sub-types; where its 0x97 length field disagrees with its own examples, the examples are followed) | Gt06ProtocolDecoder read for facts (0x10, 0x32/0x33, 0x9B, the 0x2A answer form; these have no Concox document found); test vectors from Gt06ProtocolDecoderTest (gt06_test.go, lbs_test.go, more_test.go); the LBS and WiFi layouts in lbs.go were checked against them |
| `teltonika` | Teltonika's public protocol description: codecs 8, 8E, 16, 12, 13, 14 and 15, the TCP and UDP framing and acknowledgements (wiki "Codec", web.archive.org snapshot of 2026-01-12, as the live wiki refused access; its codec 15 section from a search excerpt); the FMB SMS/GPRS command list and the FMB `setparam` parameter lists (IDs 10000 to 10255) for the named commands; the FMB AVL ID list (firmware 03.18.18 and newer, web.archive.org snapshot of 2020-10-24) for the IO element table: IDs, units and multipliers are facts, names are our own. The wiki's codec 14 nACK example has a wrong CRC (0x32AC; the data computes to 0x635E) | TeltonikaProtocolDecoder read for the GH codec 7 layout (the only document found, "GH3000 Data protocol v1.08", is marked confidential and was not used); test vectors: the wiki's codec 13, 14 and 15 packets, and Traccar's codec 7 packets (one with its CRC completed: Traccar's is a byte short) |
| `tk103` | The GPS103 (Coban) protocol document (login, heartbeat, report frames and keywords); the Coban GPRS command letters | Gps103ProtocolEncoder read to confirm it has no reboot command (one profile comment notes that Traccar sends commands without the terminator) |
| `queclink` | Queclink GV300N @Track Air Interface Protocol V3.01 (TRACGV300NAN001), including its section 4 on the HEX format (https://controlsatperu.com/Manuales/GV300N/Document/GV300N%20@Track%20Air%20Interface%20Protocol%20V3.01.pdf); GV300 @Track Air Interface Protocol V2.40. The test frames in decode_test.go are the GV300N V3.01 document's examples; its HEX examples often contradict its tables, so they are used only where self-consistent (GTDOS). GV350M V3.11 was not read (the traccar.org page has no downloadable copy) | Gl200BinaryProtocolDecoder and Gl200FrameDecoder read for facts (the 0x2B00 record frame, GL300 masks); test vectors from Gl200BinaryProtocolDecoderTest and Gl200FrameDecoderTest (hex_test.go) |
| `meitrack` | MEITRACK GPRS Protocol V1.8 (2016-12-19), including sections 3.32 and 3.48 to 3.51 for pictures (https://www.meitrack.com/cd-download/Protocols/MEITRACK_GPRS_Protocol.pdf); T1 & T333 GPRS Protocol V1.4 (2018-12-04); T366/T366G/T366L GPRS Protocol V1.5 (2019-07-02); GPRS (CCE ID) Protocol V1.0 (2025-03-30), all from meitrack.com. The test frames in decode_test.go are those documents' examples (V1.8 sections 3.1, 3.3, 3.17, 3.19, 3.21, 3.35, 3.61, 3.63; T1/T333 V1.4 section 3.64; the CCE ID V1.0 sample) | MeitrackProtocolDecoder read for the CCC layout and confirmation (no public description) and the D00 rhythm of eight; test vectors from MeitrackProtocolDecoderTest: two CCC packets and the D00 header (vectors_test.go) |
| `ruptela` | Ruptela "Ruptela Protocol" v1.113 (doc* test packets are its examples; a copy at https://pdfcoffee.com/ruptela-protocol-v1113-pdf-free.html); Ruptela "SMS Command List" for 4th and 5th generation devices (https://content.gps-trace.com/assets/634dd45f-332e-4687-9368-dded9923c494). Neither names a data-period parameter | RuptelaProtocolDecoder and RuptelaProtocolEncoder read for the file transfer, trouble code layout and command IDs; test vectors: devRecords, devIdent, devGetio, devExt, the files packet (command 37) and the DTC payload (re-framed: its length field is wrong) from Traccar's decoder tests |
| `jt808` | JT/T 808-2013, in its published English translation (roadragon.com), clauses and tables cited in the code (4.4.2 escaping; tables 12, 18, 24, 25), the 2019 header change and the 0x0A00/0x8A00 key bodies; the JT/T 808-2011 registration layout from public translations; Jimi IoT (Concox) VL and JC series behaviour (0x6006 and 0x0900 text answers). Active safety (Jiangsu T/JSATL12-2017: items 0x64 to 0x67, 0x1210/0x1211/0x1212, 0x9208/0x9212) and JT/T 1078-2016 signalling: facts from the documentation and model files of cuteLittleDevil/go-jt808 (MIT), https://github.com/cuteLittleDevil/go-jt808; no code used. The official texts are paid or not freely published and were not read. The RSA block rule (PKCS #1 v1.5 in k-11 byte pieces) is our choice, as the standard fixes none | Jt808ProtocolDecoder and Jt808ProtocolEncoder, read for vendor behaviour and the 0x64/0x65 layout; test vectors from Jt808ProtocolDecoderTest (decode_test.go; the 0x64 ADAS frame, which Traccar quotes unescaped with a wrong check code, escaped and read with checkCrc off; a vendor 0x66 frame) |
| `h02` | HuaSunTeK "GPS Tracker Communication Protocol" V1.0.5 (2017) and Cantrack "CANTRACK PROTOCOL" A/1 (2017, section D for the Y-model record), manufacturers' documents hosted at traccar.org/protocol/5013-h02/ | The H02 decoder, frame decoder and encoder, read for NBR, LINK, the binary validity nibble and the S71 interval form; test vectors bDoc, bText, b45 from its decoder tests; the Y-model example is Cantrack's |
| `osmand` | traccar.org/osmand (the OsmAnd parameters, time forms, knots); traccar.org/configuration-file and traccar.org/forward (forward.url, forward.type json, forward.header) | The OsmAnd decoder, read for behaviour; the Position and Device models for the JSON names a forwarding server sends; Traccar Client SDK (HttpUploader.kt: the form POST, knots, battery) and Traccar Client (main_screen.dart: the SOS alarm); test vectors from OsmAndProtocolDecoderTest and the OsmAnd page |
| `ais140` | AIS-140 (ARAI, October 2016) with Amendment 1 (11 December 2017), Amendment 2 (5 December 2018) and Amendment 3 (04/2026, printed 7 May 2026): the login, data, health, emergency and emergency SMS packet tables (4A(1), 4A(2), 3B, 4C), alert IDs, the OTA commands of Table 4D and their responses, the checksum (item 18), the unique device ID (3.1.1.12), the RFID trailer ID (3.1.1.28), and the activation and health check SMS (Amendment 2, 8.4). An ARAI publication, not redistributed here | ItsProtocolDecoder read for the vendor tail layouts (RLP, CTPL); test vectors: all 37 packets of ItsProtocolDecoderTest (ais140_test.go fieldVectors, traccar_test.go) |
| `wialon` | Gurtam "Wialon IPS" v2.0 (10/2014), a copy at https://www.bitlite.ru/files/Wialon IPS_en_v_2_0.pdf (later revisions at https://wialon.com/hw/files/); the 1.1 forms from the same document and Traccar's vectors. Test vectors include the document's compressed login and data examples and its CRC example | WialonProtocolDecoderTest only, for test vectors (2.0 login, SD, D, UDP D; 1.1 SD, UDP SD, D, B, motion and cell packets; ping). Its 2.0 login vector does not match its own checksum and is tested as a bad-checksum case |
| `galileosky` | Galileosky "User's Manual GalileoSky GPS/GLONASS v5.0", firmware 0200, chapter on the server exchange protocol (packet layout, confirmation, tag table, status bits, command packet, command list), a copy at https://www.discoverytelecom.eu/upload/iblock/f0d/UserManual_En_5x.pdf; the "Protocol" command of "User Manual Galileosky 5.1" (base.galileosky.com). The manual's 0x30, 0x33, 0x70, 0x80 and 0xC1 examples are test vectors, inside a packet of our own | GalileoProtocolDecoder and GalileoFrameDecoder read for the lengths of later tags (0x47, 0x48, 0x5A, 0x5C, 0x5D, 0xD3, 0xE2 to 0xEA, 0xFA, 0xFD, 0xFE) and the 0x07 picture layout; test vectors devFull, devFive, devAnswerInall, devAnswerOut, devHead, devUserArray, devExtended |
| `suntech` | No manufacturer document: Suntech's protocol documents are not public (the one copy found, an ST215/ST240 Operation Description at traccar.org/protocol/5011-suntech/, is marked confidential and was not used). The answer shape `ST300CMD;Res;<id>;<sw>;Enable1` was confirmed in Traccar forum posts | SuntechProtocolDecoder, SuntechProtocolEncoder and SuntechFrameDecoder read for facts; test vectors from SuntechProtocolDecoderTest |
| `calamp` | CalAmp "LM Direct Reference Guide" could not be read; only its service-type and message-type lists were seen, through a GpsGate summary | CalAmpProtocolDecoder and CalAmpProtocol read for facts; test vectors from CalAmpProtocolDecoderTest |
| `atrack` | "ATrack Protocol Document", revision 1.3.6 (2012-12-21), ATrack Technology Inc., hosted at https://www.traccar.org/protocol/5044-atrack/ (marked confidential by its publisher; read for facts only, no text taken) | AtrackFrameDecoder, AtrackProtocolDecoder, AtrackProtocolEncoder read for facts; test vectors from AtrackProtocolDecoderTest and AtrackFrameDecoderTest. Testing showed the binary CRC is CRC-16/ARC from the length field on, and that some real ASCII CRCs do not follow the document's rule |
| `eelink` | "EELINK Device Protocol V2.0" (2017-05-01) and "EELINK Terminal Communication Protocol Second Edition V1.8.4", hosted at https://www.traccar.org/protocol/5064-eelink/ (they carry the publisher's copyright notice; read for facts only, no text taken); the V2.0 document's examples are test vectors | EelinkProtocolDecoder, EelinkProtocolEncoder, EelinkProtocol read for facts (the mask bit 7 LTE block and the 0x25 alarm code come from Traccar only); test vectors from EelinkProtocolDecoderTest and EelinkProtocolEncoderTest |
| `watch` | "Communication Protocol" VER V1.7_C (3G Electronics), https://www.traccar.org/protocol/5093-watch/Communication%20Protocol.doc; its examples are test vectors | WatchFrameDecoder, WatchProtocolDecoder, WatchProtocolEncoder read for facts (the 3G to SG vendor, the health frames and the binary escaping come from Traccar only); test vectors from WatchProtocolDecoderTest, WatchFrameDecoderTest and WatchProtocolEncoderTest |

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
  beyond the attribution comments; repeated on 2026-10-12 over the v0.2.0
  code, with the same result.
- Traccar 6.16.0 (Docker image traccar/traccar:6.16.0, source tag v6.16.0)
  was run as the independent peer on 2026-10-12: every protocol's
  positions, the SOS alarms and the command frames, as the README's
  Interop section lists.
- Several manufacturers' documents used for v0.2.0 (ATrack, Eelink, and
  the Teltonika GH3000 and Suntech copies, which were not used) carry
  "confidential" or copyright notices although they are hosted publicly.
  Only facts (layouts, IDs, codes) were taken from them, and no text.
- A review for specification prose (2026-10-11) found no copied passages
  and no normative sentences in comments; comments cite clause, table and
  figure numbers in our own words. One four-word phrase of AIS-140 is
  quoted, with attribution, in `ais140/standard.go`.
- Not done: a line-by-line similarity check against Traccar's decoders.
  Both projects are Apache-2.0, so such a check is about crediting
  exactly, not about the licence.
- The licences of Traccar, Traccar Client and the Traccar Client SDK were
  confirmed from their LICENSE files on 2026-10-11 (Apache-2.0).
