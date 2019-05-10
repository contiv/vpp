#!/usr/bin/env bash
set -ex
# setup the environment file. Export the env-vars passed as args to 'vagrant up'
# This script will also: add keys, update and install pre-requisites

echo Args passed: [[ $@ ]]

cat <<EOF >/etc/profile.d/envvar.sh
export http_proxy='${http_proxy}'
export https_proxy='${https_proxy}'
export HTTP_PROXY='${http_proxy}'
export HTTPS_PROXY='${https_proxy}'
EOF

source /etc/profile.d/envvar.sh

if [ "$1" = "install" ];then
    echo "Updating apt lists..."
    sudo -E apt-get update

    echo "Installing dependency packages..."
    sudo -E apt-get install -y apt-transport-https \
                      ca-certificates \
                      curl \
                      software-properties-common \
                      htop

    echo "Adding Kubernetes repo..."
    curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo -E apt-key add -
    sudo -E add-apt-repository "deb http://apt.kubernetes.io/ kubernetes-xenial main"

    if [ "${node_os_release}" == "16.04" ] ; then
      echo "Adding Docker repo..."
      curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo -E apt-key add -
      sudo -E add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu xenial stable"
    fi

    echo "Updating apt lists..."
    sudo -E apt-get update -q

    echo "Installing Kubernetes Components..."
    sudo -E apt-get install -qy kubelet=${k8s_version}-00 \
                      kubectl=${k8s_version}-00 \
                      kubeadm=${k8s_version}-00 kubernetes-cni=0.6.0-00

    echo "Installing Docker..."
    if [ "${node_os_release}" == "16.04" ] ; then
      sudo -E apt-get install -y docker-ce=${docker_version}~ubuntu
    else
      sudo -E apt-get install -y docker.io=18.06.1-0ubuntu1.2~18.04.1
    fi

    systemctl stop docker
    modprobe overlay

    echo '{"storage-driver": "overlay2"}' > /etc/docker/daemon.json
    rm -rf /var/lib/docker/*
    systemctl start docker
fi

#Setup the proxy if needed
if [ "${http_proxy}" != "" ] ; then
  sudo mkdir -p /etc/systemd/system/docker.service.d
  sudo echo "[Service]
Environment=\"HTTP_PROXY='${http_proxy}'"" >> /etc/systemd/system/docker.service.d/http-proxy.conf
  sudo systemctl daemon-reload
  sudo systemctl restart docker
fi
if [ "${https_proxy}" != "" ] ; then
  sudo mkdir -p /etc/systemd/system/docker.service.d
  sudo echo "[Service]
Environment=\"HTTPS_PROXY='${https_proxy}'"" >> /etc/systemd/system/docker.service.d/http-proxy.conf
  sudo systemctl daemon-reload
  sudo systemctl restart docker
fi

## more docker stuff
#systemctl stop docker
#modprobe overlay
#
#echo '{"storage-driver": "overlay2"}' > /etc/docker/daemon.json
#rm -rf /var/lib/docker/*
#systemctl start docker

#explicitly set max number of concurrent ssh connections
echo 'MaxStartups 20' >> /etc/ssh/sshd_config
sudo service sshd restart

if [ "${dep_env}" == "dev" ]; then
  echo "Downloading Go '${go_version}'..."
  curl --silent https://storage.googleapis.com/golang/go"${go_version}".linux-amd64.tar.gz > /tmp/go.tar.gz

  echo "Extracting Go..."
  tar -xvzf /tmp/go.tar.gz --directory /home/vagrant >/dev/null 2>&1

  echo "Setting Go environment variables..."
  mkdir -p /home/vagrant/gopath/bin
  mkdir -p /home/vagrant/gopath/pkg
  chmod -R 777 /home/vagrant/gopath

  echo 'export GOROOT="/home/vagrant/go"' >> /home/vagrant/.bashrc
  echo 'export GOPATH="/home/vagrant/gopath"' >> /home/vagrant/.bashrc
  echo 'export PATH="$PATH:$GOROOT/bin:$GOPATH/bin"' >> /home/vagrant/.bashrc

  update-locale LANG=en_US.UTF-8 LANGUAGE=en_US.UTF-8 LC_ALL=en_US.UTF-8
  echo 'All done!'
fi

#Disable swap
swapoff -a
sed -e '/swap/ s/^#*/#/' -i /etc/fstab

# ipv6 networking setup
if [ "${ip_version}" == "ipv6" ]; then
    # enable ip6 forwarding
    sysctl -w net.ipv6.conf.all.forwarding=1

    # override default nameserver
    rm /etc/resolv.conf
    echo "nameserver ${base_ip}100" > /etc/resolv.conf

    # add default ipv6 route via mgmt interface, to make kube-proxy work properly
    if [ "${dep_scenario}" == "nostn" ]; then
        ip -6 route add default via ${base_ip}100 dev enp0s9 || true
    else
        ip -6 route add default via ${base_ip}100 dev enp0s8 || true
    fi
fi

#Load uio_pci_generic driver and setup the loading on each boot up
installPCIUIO() {
   modprobe uio_pci_generic
      # check if the driver is not already added into the file
      if ! grep -q "uio_pci_generic" /etc/modules; then
         echo uio_pci_generic >> /etc/modules
         echo "Module uio_pci_generic was added into /etc/modules"
      fi
}

#Load vfio_pci driver and setup the loading on each boot up
installPCIVFIO() {
   modprobe vfio_pci
      # check if the driver is not already added into the file
      if ! grep -q "vfio_pci" /etc/modules; then
         echo vfio_pci >> /etc/modules
         echo "Module vfio_pci was added into /etc/modules"
      fi
}

#Selects an interface that will be used for node interconnect
createVPPconfig() {
mkdir -p /etc/vpp
touch /etc/vpp/contiv-vswitch.conf
  cat <<EOF >/etc/vpp/contiv-vswitch.conf
unix {
   nodaemon
   cli-listen /run/vpp/cli.sock
   cli-no-pager
   coredump-size unlimited
   full-coredump
   poll-sleep-usec 100
}
dpdk {
   dev 0000:00:08.0
}
nat {
   endpoint-dependent
   translation hash buckets 1048576
   translation hash memory 268435456
   user hash buckets 1024
   max translations per user 10000
}
acl-plugin {
   hash lookup heap size 512M
   hash lookup hash memory 512M
   use tuple merge 0
}
api-trace {
   on
   nitems 5000
}
socksvr {
   default
}
statseg {
   default
}
EOF
}

# Pull image used in k8s-systest "max_pod" scale
docker pull kahou82/kubia

createVPPconfig
split_node_os_release="$(cut -d "." -f 1 <<< "${node_os_release}")"
if [ "$split_node_os_release" = '16' ]; then
  kernelModule=$(lsmod | grep uio_pci_generic | wc -l)
  if [[ $kernelModule -gt 0 ]]; then
    echo "PCI UIO driver is loaded"
  else
    installPCIUIO
  fi
  if [ "${dep_scenario}" = 'nostn' ]; then
      #shutdown interface
      ip link set enp0s8 down
      echo "#auto enp0s8" >> /etc/network/interfaces
  fi
else
  kernelModule=$(lsmod | grep vfio_pci | wc -l)
  if [[ $kernelModule -gt 0 ]]; then
    echo "PCI VFIO driver is loaded"
  else
    installPCIVFIO
  fi
  if [ "${dep_scenario}" = 'nostn' ]; then
    #shutdown interface
    ip link set enp0s8 down
  fi
fi
