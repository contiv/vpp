#!/bin/sh
echo "Starting Contiv VPP ..."
echo ""

cd ../vagrant
sh ./vagrant-dummy-start

echo "Setting Kubernetes proxy ..."
vagrant ssh k8s-master -c "nohup kubectl proxy --port=8080 > /dev/null 2>&1 < /dev/null &"

cd ../ui
sh ./setVMs.sh

echo "Starting vagrant ..."

cd ./vagrant
vagrant up

echo ""
echo "Application has been deployed. Open URL http://localhost:4300 in your browser with disabled security."
