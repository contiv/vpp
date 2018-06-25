#!/usr/bin/env bash

#confirm asks a question and based on user input it returns either 1-yes or 0-no.
confirm () {

   while true
   do
    read -r -p "$1 [Y/n] " input

    case $input in
        [yY][eE][sS]|[yY])
    echo 1
    return
    ;;

        [nN][oO]|[nN])
    echo 0
    return
           ;;

        *)
    ;;
    esac
   done
}


#loads uio_pci_generic driver and setup the loading on each boot up if requested
installPCIUIO() {
   modprobe uio_pci_generic
   if [[ $(confirm "Do you want the PCI UIO driver to be loaded on boot up?") -eq 1 ]]; then
      # check if the driver is not already added into the file
      if ! grep -q "uio_pci_generic" /etc/modules; then
         echo uio_pci_generic >> /etc/modules
         echo "Module uio_pci_generic was added into /etc/modules"
      fi
   fi
}

#selects an interface that will be used for node interconnect
selectNodeIntreconnectIf() {
   interfaces=`lshw -class network -businfo | grep pci`
   if [[ -z "$interfaces" ]]; then
      echo "No network devices found."
      exit 1
   fi

   echo "The following network devices were found"
   echo "$interfaces" | sed 's/pci@//g' | awk '{printf "%s) %s %s\n", NR, $2, $1}'

   nicCnt=$(echo "$interfaces" | wc -l)

   selectedDevice=0

   #process input from user
   while true
   do
      read -r -p "Select interface for node interconnect [1-$nicCnt]:" selection
      case "$selection" in
         [0-9]*)
            if [[ "$selection" -gt "$nicCnt" || "$selection" -eq 0 ]]; then
               echo "Selected option is out of range"
            else
               selectedDevice=$(echo "$interfaces" | sed "${selection}q;d")
               break
            fi
            ;;
         *)
            echo "Invalid input"
            ;;
      esac
   done

   device=$(echo "$selectedDevice" | awk '{print $2}')
   pciAddr=$(echo "$selectedDevice" | awk '{print $1}' | sed 's/pci@//g')

   if [[ $(confirm "Device '$device' must be shutdown, do you want to proceed?") -ne 1 ]]; then
      exit 1
   fi

   #check whether startup.conf exist
   startup="
unix {
   nodaemon
   cli-listen /run/vpp/cli.sock
   cli-no-pager
   poll-sleep-usec 100
}
api-trace {
    on
    nitems 500
}
dpdk {
   dev $pciAddr
}
"
   echo "$startup"

   if [[ $(confirm "File /etc/vpp/contiv-vswitch.conf will be modified, do you want to proceed?") -ne 1 ]]; then
      exit 1
   fi

   #create vpp startup config
   echo "$startup" > /etc/vpp/contiv-vswitch.conf

   #shutdown interface
   ip link set "$device" down
}

## Setup begins

echo "#########################################"
echo "#   Contiv - VPP                        #"
echo "#########################################"

# Make sure only root can run this script
if [[ $EUID -ne 0 ]]; then
   echo "ERROR: This script must be run as root." 1>&2
   exit 1
fi


if [[ $(confirm "Do you want to setup multinode cluster?") -eq 1 ]]; then

   kernelModule=$(lsmod | grep uio_pci_generic | wc -l)
   if [[ $kernelModule -gt 0 ]]; then
         echo "PCI UIO driver is loaded"
   else
      echo "PCI UIO driver is not loaded"
      if [[ $(confirm "Do you want to load PCI UIO driver?") -eq 1 ]]; then
           installPCIUIO
      else
           echo "Unless the driver is loaded, VPP will not be able to grab the NIC."
           exit 0
      fi

   fi
   selectNodeIntreconnectIf
fi

if [[ $(confirm "Do you want to pull the latest images?") -eq 1 ]]; then
    bash <(curl -s https://raw.githubusercontent.com/contiv/vpp/master/k8s/pull-images.sh)
fi

if [[ $(docker ps  | grep contiv-stn | wc -l) -gt 0 ]]; then
    echo "STN Daemon is already running"
    if [[ $(confirm "Do you want to restart STN Daemon?") -eq 1 ]]; then
        docker stop contiv-stn
        docker rm contiv-stn
        bash <(curl -s https://raw.githubusercontent.com/contiv/vpp/master/k8s/stn-install.sh)
    fi
elif [[ $(confirm "Do you want to install STN Daemon?") -eq 1 ]]; then
     bash <(curl -s https://raw.githubusercontent.com/contiv/vpp/master/k8s/stn-install.sh)
fi

#if [[ $(docker ps  | grep contiv-cri | wc -l) -gt 0 ]]; then
#    echo "Cri-shim is already running"
#    if [[ $(confirm "Do you want to restart cri-shim?") -eq 1 ]]; then
#        docker stop contiv-cri
#        docker rm contiv-cri
#        bash <(curl -s https://raw.githubusercontent.com/contiv/vpp/master/k8s/cri-install.sh)
#    fi
#elif [[ $(confirm "Do you want to install cri-shim?") -eq 1 ]]; then
#     bash <(curl -s https://raw.githubusercontent.com/contiv/vpp/master/k8s/cri-install.sh)
#fi

echo "Configuration of the node finished successfully."
