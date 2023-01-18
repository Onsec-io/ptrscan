#!/bin/bash
docker build . -t 'ptrscan' --no-cache

docker run --rm -t\
  -e X_THREADS=20 \
  -v "$PWD"/input:/opt/input \
  -v "$PWD"/output:/opt/output \
  ptrscan
