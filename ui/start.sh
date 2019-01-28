#!/bin/sh

echo "Starting Contiv VPP ..."

cd ../vagrant
sh ./vagrant-dummy-start

cd ../ui
sh ./os-check.sh
