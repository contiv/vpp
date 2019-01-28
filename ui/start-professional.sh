#!/bin/sh

echo "Starting Contiv VPP ..."

cd ../vagrant
sh ./vagrant-start

cd ../ui
sh ./os-check.sh
