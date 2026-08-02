# Logging record and segment format

## Primary envelope

The encoded primary record is limited to 4096 bytes. It contains a fixed header and versioned TLV fields.

The fixed header identifies:

- magic value;
- format version;
- writer version;
- total record length;
- record kind and flags;
- UTC timestamp;
- process clock value;
- process-start identity;
- sequence number;
- record checksum.

Unknown TLV fields can be skipped using their type and length. Newer writers may therefore add fields without making the entire record unreadable to an older parser.

## Time and ordering

Every record contains UTC wall time and a process clock value. The clock value is not assumed to remain globally monotonic forever. Process-start identity, sequence, prior clock values, and UTC time allow readers to detect reset or wrap and calculate local deltas appropriately.

Cross-host ordering remains approximate unless an external time-quality source is supplied.

## Truncation

A crash can leave an incomplete final record. Readers recover every complete preceding record, stop at the incomplete frame, and report a warning. They do not treat the entire segment as corrupt.

## Segments

Only one writer owns an open segment. Closed segments receive:

- content hash;
- previous-segment hash;
- first and last global sequence;
- record count;
- optional compressed path;
- optional runtime signature reference.

SQLite stores offsets and selected metadata but is rebuildable.

## Attachments

Large bodies are stored outside the 4 KiB event stream. The event contains a compact typed reference. Attachment segments have independent hash chains, manifests, rotation, compression, retention, size limits, and probabilistic overload sampling.

Attachments may be sampled out, but the primary event records the decision. Critical categories can bypass sampling.
