#!/usr/bin/env bash

if [ -d build ]; then
  rm -rf build;
fi
mkdir build && cd build

# https://unix.stackexchange.com/questions/283868/bash-script-detecting-change-in-files-from-a-directory
while inotifywait -e modify /kyber/**/*; do
  cmake -DBUILD_SHARED_LIBS=ON -GNinja .. && \
  ninja && \
  sleep 10
done
