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
echo "Application has been deployed on http://localhost:4300"
echo ""

cd ../

case "$OSTYPE" in

  darwin*)
    echo "For accessing k8s nodes via 'vagrant ssh', cd into vpp/vagrant directory."

    Open -n -a "Google Chrome" --args --disable-web-security --user-data-dir=/tmp/chrome http://localhost:4300 || echo "Open URL http://localhost:4300 in your browser with disabled web security."
    ;;

  linux*)
    gnome-terminal --working-directory=$PWD/../vagrant
    echo "For accessing k8s nodes via 'vagrant ssh', cd into vpp/vagrant directory."

    google-chrome --user-data-dir=”/var/tmp/Chrome” --disable-web-security "http://localhost:4300" || echo "Open URL http://localhost:4300 in your browser with disabled web security."
    ;;

  *)
    start powershell -noexit cd ../vagrant
    echo "For accessing k8s nodes via 'vagrant ssh', cd into vpp/vagrant directory."

    start chrome.exe --user-data-dir="C://Chrome dev session" --disable-web-security http://localhost:4300 || echo "Open URL http://localhost:4300 in your browser with disabled web security."
    ;;
esac
