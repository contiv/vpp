#!/bin/sh
echo "Setting VMs port forwarding ..."
sh ./setVMs.sh
echo "Port forwarding has been set."

echo "Starting vagrant ..."
cd ./vagrant && vagrant up

echo ""
echo "Application has been deployed. Open URL http://localhost:4200 in your browser with disabled security."
