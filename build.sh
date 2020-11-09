#!/usr/bin/env bash

BUILD_FOLDER=build

mkdir BUILD_FOLDER && cd BUILD_FOLDER
cmake -DBUILD_SHARED_LIBS=ON -GNinja .. && ninja
