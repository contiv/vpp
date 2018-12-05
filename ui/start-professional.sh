#!/bin/sh
echo "Starting Contiv VPP ..."
echo ""

cd ../vagrant
sh ./vagrant-start

cd ../ui
sh ./setVMs.sh

echo "Starting vagrant ..."

cd ./vagrant
vagrant up

echo ""
echo "Application has been deployed. Open URL http://localhost:4300 in your browser with disabled security."
