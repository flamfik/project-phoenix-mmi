# Milestone M3 - Resource Laboratory

Status: **READY**

Entry evidence: Session 074, operational graph v66

## Mission

Build a read-only resource research layer over Phoenix SDK for graphics,
fonts, strings, language payloads and offline UI reconstruction. M3 studies
resource representation and relationships; it does not modify firmware.

## Entry gate

- M1 Firmware Archaeology is COMPLETE;
- M2 Analysis Toolkit is COMPLETE with 8/8 exit criteria;
- the sanitized integration chain is deterministic;
- safe mutation and installable-artifact gates remain false;
- YIM integrity and LOD semantic uncertainty remain explicit.

Session 074 passes this gate. M3 work is authorized to begin.

## Initial session route

Session 075 will freeze the M3 capability baseline and exit criteria before
new resource analysis is implemented. Expected workstreams are:

- resource identity and provenance;
- embedded and standalone XIM2/YIM catalogs;
- pixel-unit and palette hypotheses;
- font and string discovery;
- language-pack topology;
- offline publication-safe preview models.

## Safety boundary

M3 may parse, decode privately, compare and render synthetic or legally
controlled data offline. It may not synthesize unknown integrity fields,
replace resource bytes, repack update media, create installable artifacts,
execute firmware or communicate with a vehicle.
