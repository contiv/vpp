if [ -z $1 ];then
        echo "Usage: ./vbox_bash.sh <guest-vm-id> <command-string>"
        echo 'Obtain guest-vm-id by running "VBoxManage list runningvms" as user vagrant.'
        echo 'Example: ./vbox_bash.sh 28daec0f-bbbe-400b-9db2-b992a46d2a7e "sudo vppctl show interface"'
        exit 1
fi

vboxmanage --nologo guestcontrol $1 run --username vagrant --password vagrant --exe "/bin/bash" --wait-stdout --wait-stderr -- bash -c "$2"