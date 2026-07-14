#!/usr/bin/env bash
set -euo pipefail
mkdir -p firmware/original research/firmware-5570/work
printf '%s\n' \
  'Local laboratory directories created.' \
  'Copy legally obtained ISO images into firmware/original/.' \
  'These paths are excluded from Git.'
