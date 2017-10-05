#!/bin/bash

cd contiv-agent/dev
./build.sh

cd ../prod
./build.sh

cd ../../contiv-plugins/dev
./build.sh

cd ../prod
./build.sh
