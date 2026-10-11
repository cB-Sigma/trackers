# Changelog

## v0.2.0

The v0.1.0 Go API is kept; everything below is added to it.

### New protocols

- `wialon`: Wialon IPS 1.1 and 2.0 over TCP and UDP, with CRC, compressed
  packets, black box, driver messages, pictures and tachograph files.
  Commands: custom, message, picture, DDD and upload.
- `galileosky`: the Galileosky tag protocol. Reads multi-record packets
  and the tag table, with status bits as alerts, and pictures; confirms
  with CRC-16/MODBUS. Command packets are correlated by number, with named
  commands.
- `suntech`: Suntech older and Universal text protocols and Universal
  binary; named commands correlated with their answers.
- `calamp`: CalAmp LM Direct over UDP (event, locate, mini event, user data,
  ACK), with server acknowledgements and user data commands correlated by
  sequence.
- `atrack`: ATrack binary and ASCII positions with custom fields, the
  keep-alive, and tagged `AT$` commands with correlation and the command
  password.
- `eelink`: Eelink protocol 1.x and 2.0 packages over TCP and UDP, with
  0x80 instructions correlated by UID.
- `watch`: the 3G/SeTracker bracket protocol. Reads positions, alarms and
  health readings; commands are correlated by keyword, with named locate,
  reboot and interval, and SOS numbers.

### Existing protocols

- `teltonika`:
  - Codec 15 messages and GH Codec 7 data are read.
  - The FMB IO element table (`IOName`, `IOElements`) and the `ioNames`
    profile option, which adds named status keys alongside the existing
    ones.
  - Frame builders for codecs 13, 14 and 15.
  - `interval` is now a named command by default, as FMB `setparam`
    10000/10050/10100/10150/10200/10250. It used to fail as unsupported
    unless the profile gave a template.
- `queclink`: the @Track HEX (binary) format is read on the same connection
  as ASCII: location, event, information, heartbeat and acknowledgement
  frames, and the 0x2B00 record frame. A junk HEX frame now warns
  `messageUnreadable` instead of `unknownCodec`.
- `jt808`:
  - JT/T 808-2011 registrations (`protocolVersion` status).
  - RSA body encryption (`rsaPrivateKey`, `encryptCommands`), with the
    0x0A00/0x8A00 key exchange.
  - Active-safety items 0x64 to 0x67 as alerts with alarm IDs and labels.
  - The attachment messages 0x1210/0x1211/0x1212 are answered, and the
    0x9208 attachment upload command is framed.
  - JT/T 1078 signalling commands; their 0x1003 and 0x1205 answers are
    decoded and correlated.
- `gt06`:
  - Reads 0x10, 0x19, 0x23, 0x27, 0x2A, 0x17 (normal frame), 0x9B, 0x7979
    0x32/0x33, and the 4G frames 0xA0 to 0xA5 and 0xA7.
  - `AddressReply` (0x97).
  - The GK310 alarm codes; alarm records now carry the cell.
- `h02`: the Cantrack Y-model binary record.
- `meitrack`:
  - D00 pictures are reassembled and fetched, and the D01 picture list is
    read.
  - CCC batches are decoded and confirmed.
  - Event 39 gives the picture name; the `fetchPictures` option fetches it.
- `ruptela`:
  - Commands 2, 3, 4, 9 (per trouble code), 14, 30, 32, 34 and 37 are
    decoded; 35 and 38 are acknowledged.
  - Binary commands `getVersion`, `setConnection`, `setOdometer`,
    `photoList` and `photo`.
  - The test that uses an unknown command now uses 99.
- `ais140`:
  - RLP packets (date before the fix flag) are no longer read as logins.
  - Digital I/O is found after any number of neighbour cells.
  - Vendor tail layouts: `vendor`, `tail`, `VendorTails`.
  - Every packet in Traccar's ITS tests decodes.
- `tk103`: documents that reboot is a profile template only (no public
  GPRS command).

### Checked

- Every protocol against Traccar 6.16.0 in Docker: positions, alarms and
  command frames. The `interop` module of trackers-sim holds the tests;
  the README lists the results and each difference with its reason.
