# Milestone M4 - Runtime Research

Status: **COMPLETE**

Closure evidence: Session 092, operational graph v84

## Mission

Build a static-first runtime research model covering tasks, message passing,
device services, resource consumers and a safe host-side emulation strategy.
M4 must connect static structures to independently reproducible runtime
hypotheses without executing untrusted firmware.

## Entry gate

- M1 Firmware Archaeology is COMPLETE;
- M2 Analysis Toolkit is COMPLETE;
- M3 Resource Laboratory is COMPLETE with 8/8 criteria;
- the M3 synthetic integration chain is deterministic;
- firmware mutation and installable-artifact gates remain false.

## Completed route

- Session 084: capability baseline and eight exit criteria;
- Session 085: static task/service inventory;
- Session 086: bounded negative IPC probe;
- Session 087: resource consumer matrix;
- Session 088: device boundary catalog;
- Session 089: anonymous runtime object topology;
- Session 090: isolated host runtime contract;
- Session 091: confidence-graded runtime evidence graph;
- Session 092: deterministic integration and M4 closure.

All eight criteria pass. M4 is COMPLETE and M5 Phoenix UI Prototype is READY.

## Safety boundary

M4 begins with static analysis and synthetic fixtures. It may not execute
firmware, emulate vehicle authorization, communicate with a vehicle, bypass
Component Protection, synthesize unknown integrity fields or create
installable media.
