#!/usr/bin/env bash

BUILD_FOLDER=build

mkdir $BUILD_FOLDER && cd $BUILD_FOLDER
cmake -GNinja -DCMAKE_BUILD_TYPE=Release .. && ninja
