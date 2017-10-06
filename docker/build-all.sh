#!/bin/bash

cd contiv-vswitch/dev
./build.sh

cd ../prod
./build.sh

cd ../../contiv-plugins/dev
./build.sh

cd ../prod
./build.sh
