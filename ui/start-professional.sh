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
echo "Application has been deployed on http://localhost:4300"
echo ""

case "$OSTYPE" in

  darwin*)
    Open -n -a "Google Chrome" --args --disable-web-security --user-data-dir=/tmp/chrome http://localhost:4300 || echo "Open URL http://localhost:4300 in your browser with disabled web security."
    ;;

  linux*)
    google-chrome --user-data-dir=”/var/tmp/Chrome” --disable-web-security "http://localhost:4300" || echo "Open URL http://localhost:4300 in your browser with disabled web security."
    ;;

  *)
    start chrome.exe --user-data-dir="C://Chrome dev session" --disable-web-security http://localhost:4300 || echo "Open URL http://localhost:4300 in your browser with disabled web security."
    ;;
esac
