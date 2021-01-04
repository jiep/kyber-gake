#!/usr/bin/env bash

BUILD_FOLDER=build

mkdir -p $BUILD_FOLDER && cd $BUILD_FOLDER
cmake -DCMAKE_BUILD_TYPE=Release .. && make
