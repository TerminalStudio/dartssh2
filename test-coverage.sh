#!/bin/bash
OBS_PORT=9292

dart --disable-service-auth-codes \
  --enable-vm-service=$OBS_PORT \
  --pause-isolates-on-exit \
  test/test_all.dart &

pub global run coverage:collect_coverage \
  --port=$OBS_PORT \
  --out=coverage/coverage.json \
  --wait-paused \
  --resume-isolates

pub global run coverage:format_coverage \
  --lcov \
  --in=coverage/coverage.json \
  --out=coverage/lcov.info \
  --packages=.packages \
  --report-on=lib
