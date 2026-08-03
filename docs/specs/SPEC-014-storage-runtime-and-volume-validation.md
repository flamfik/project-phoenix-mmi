# SPEC-014 - Storage runtime and embedded-volume validation

- Version: 0.1
- Maturity: ALPHA
- Evidence: Sessions 003, 004 and 009
- Related questions: RQ-005, RQ-010, RQ-023, RQ-024

## Purpose

This specification separates three questions that must not be conflated:

1. Does the executable contain filesystem/runtime support?
2. Does the principal BIN itself contain a structurally valid embedded volume?
3. Which device and format provide navigation map data at runtime?

Session 009 answers the first, produces a bounded negative result for the second and leaves the third open.

## Runtime stack evidence

The storage stack is confirmed only when both releases contain the required fixed families (`dosFs`, TFFS, FAT12, FAT16 and FAT32), preserve storage-dominant cross-version bands and expose bounded PC-relative SH-3 users of storage marker addresses.

Current status: `CONFIRMED_CROSS_VERSION_STORAGE_RUNTIME_EVIDENCE`.

## ISO-9660 validator

Every `CD001` occurrence is treated as a candidate. It validates only when:

- the preceding byte is a permitted ECMA-119 volume-descriptor type (`0`, `1`, `2`, `3` or `255`);
- the following byte is descriptor version `1`.

Session 009 finds one identifier occurrence in each release and zero valid descriptors. Status: `IDENTIFIER_CONSTANT_ONLY`.

## FAT boot-sector validator

A candidate begins 54 bytes before `FAT12`/`FAT16`, or 82 bytes before `FAT32`. It validates only with:

- a supported x86-style boot jump;
- bytes per sector in `512`, `1024`, `2048` or `4096`;
- a power-of-two sectors-per-cluster value from `1` through `128`;
- a non-zero reserved-sector count;
- one through four FAT copies;
- the expected FAT type field;
- the `0x55AA` sector signature.

Session 009 finds zero valid boot sectors.

## UDF marker probe

The bounded probe counts `BEA01`, `NSR02`, `NSR03` and `TEA01`. All counts are zero in both releases. This is not a complete UDF parser and therefore remains a marker-level negative result.

## Required interpretation

`NOT_FOUND_UNDER_TESTED_ISO9660_FAT_VALIDATORS` means only that the flat principal BIN is not itself a validated volume under these rules. It does not exclude:

- a FAT volume mounted from separate flash;
- an ISO-9660/UDF volume on optical media;
- a proprietary database above a standard filesystem;
- a device service that streams map objects without exposing a normal filesystem.

The map-media schema and backing-device layout remain `OPEN`.
