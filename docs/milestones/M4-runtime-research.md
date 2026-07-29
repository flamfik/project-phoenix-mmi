# Milestone M4 - Runtime Research

Status: **READY**

Entry evidence: Session 083, operational graph v75

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

## First route

Session 084 will freeze the M4 capability registry, research questions, exit
criteria and ordered runtime backlog. Likely workstreams are task/service
inventory, message/IPC contracts, resource-consumer ownership, device-boundary
models and synthetic host-side interfaces.

## Safety boundary

M4 begins with static analysis and synthetic fixtures. It may not execute
firmware, emulate vehicle authorization, communicate with a vehicle, bypass
Component Protection, synthesize unknown integrity fields or create
installable media.
