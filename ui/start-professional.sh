#!/bin/sh

echo "Starting Contiv VPP ..."

cd ../vagrant
sh ./vagrant-start

echo "Starting UI ..."

cd ../ui/vagrant
vagrant up

cd ../

case "$OSTYPE" in

  darwin*)
    echo "For accessing k8s nodes via 'vagrant ssh', cd into vpp/vagrant directory."

    Open -n -a "Google Chrome" --args --disable-web-security --user-data-dir=/tmp/chrome http://localhost:4300 || echo "Open URL http://localhost:4300 in your browser with disabled web security."
    ;;

  linux*)
    gnome-terminal --working-directory=$PWD/../vagrant
    echo "For accessing k8s nodes via 'vagrant ssh', cd into vpp/vagrant directory."

    google-chrome --user-data-dir="/var/tmp/Chrome" --disable-web-security "http://localhost:4300" || echo "Open URL http://localhost:4300 in your browser with disabled web security."
    ;;

  *)
    start powershell -noexit cd ../vagrant
    echo "For accessing k8s nodes via 'vagrant ssh', cd into vpp/vagrant directory."

    start chrome.exe --user-data-dir="C://Chrome dev session" --disable-web-security http://localhost:4300 || echo "Open URL http://localhost:4300 in your browser with disabled web security."
    ;;
esac

echo "Please set kubectl proxy in order to access APIs."
echo ""
echo "Application has been deployed on http://localhost:4300"
echo ""
