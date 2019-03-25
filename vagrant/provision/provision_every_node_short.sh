#!/usr/bin/env bash
set -ex
# setup the environment file. Export the env-vars passed as args to 'vagrant up'
# This script will also: add keys, update and install pre-requisites

echo Args passed: [[ $@ ]]

cat <<EOF >/etc/profile.d/envvar.sh
export http_proxy='#{http_proxy}'
export https_proxy='#{https_proxy}'
export HTTP_PROXY='#{http_proxy}'
export HTTPS_PROXY='#{https_proxy}'
EOF

source /etc/profile.d/envvar.sh

#Setup the proxy if needed
if [ "#{http_proxy}" != "" ] ; then
  sudo mkdir -p /etc/systemd/system/docker.service.d
  sudo echo "[Service]
Environment=\"HTTP_PROXY='#{http_proxy}'"" >> /etc/systemd/system/docker.service.d/http-proxy.conf
  sudo systemctl daemon-reload
  sudo systemctl restart docker
fi
if [ "#{https_proxy}" != "" ] ; then
  sudo mkdir -p /etc/systemd/system/docker.service.d
  sudo echo "[Service]
Environment=\"HTTPS_PROXY='#{https_proxy}'"" >> /etc/systemd/system/docker.service.d/http-proxy.conf
  sudo systemctl daemon-reload
  sudo systemctl restart docker
fi

if [ '#{k8s_version}' != "1.12.3" ] || [ '#{docker_version}' != "18.03.0~ce-0" ];then
    # more docker stuff
    systemctl stop docker
    modprobe overlay

    echo '{"storage-driver": "overlay2"}' > /etc/docker/daemon.json
    rm -rf /var/lib/docker/*
    systemctl start docker
fi

#explicitly set max number of concurrent ssh connections
echo 'MaxStartups 20' >> /etc/ssh/sshd_config
sudo service sshd restart

if [ "#{dep_env}" == "dev" ]; then
  echo "Downloading Go '#{go_version}'..."
  curl --silent https://storage.googleapis.com/golang/go'#{go_version}'.linux-amd64.tar.gz > /tmp/go.tar.gz

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