command_exists () {
  type "$1" > /dev/null;
}

case "$(uname -s)" in

  Darwin)
    echo ""
    echo "For accessing k8s nodes via 'vagrant ssh', cd into vpp/vagrant directory."

    Open -n -a "Google Chrome" --args --disable-web-security --user-data-dir=/tmp/chrome http://localhost:32500 || echo "Open URL http://localhost:32500 in your browser with disabled web security."
    ;;

  Linux)
    if command_exists x-terminal-emulator
    then
      x-terminal-emulator
    elif command_exists gnome-terminal
    then
      gnome-terminal
    fi
    echo ""
    echo "For accessing k8s nodes via 'vagrant ssh', cd into vpp/vagrant directory."
    echo ""

    if command_exists chromium-browser
    then
      chromium-browser --disable-web-security --user-data-dir="/var/tmp/chromium-browser" "http://localhost:32500" & > /dev/null
    elif command_exists google-chrome
    then
      google-chrome --user-data-dir="/var/tmp/Chrome" --disable-web-security "http://localhost:32500" & > /dev/null
    fi
    echo ""
    echo "Open URL http://localhost:32500 in your browser with disabled web security."
    echo ""
    ;;

  *)
    start powershell -noexit cd ../vagrant
    echo ""
    echo "For accessing k8s nodes via 'vagrant ssh', cd into vpp/vagrant directory."

    start chrome.exe --user-data-dir="C://Chrome dev session" --disable-web-security http://localhost:32500 || echo "Open URL http://localhost:32500 in your browser with disabled web security."
    ;;
esac

echo ""
echo "Application has been deployed on http://localhost:32500"
echo ""
