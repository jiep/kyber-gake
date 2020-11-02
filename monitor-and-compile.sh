#!/usr/bin/env bash

if [ -d build-ninja ]; then
  rm -rf build-ninja;
fi
mkdir build-ninja && cd build-ninja

# https://unix.stackexchange.com/questions/283868/bash-script-detecting-change-in-files-from-a-directory
while inotifywait -e modify /kyber/**/*; do
  cmake -DBUILD_SHARED_LIBS=ON -GNinja .. && \
  ninja && \
  sleep 10
done
