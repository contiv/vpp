#!/usr/bin/env bash
set -e

if [ -z $OS_VERSION ];then
    echo "No OS_VERSION provided, using 16.04."
    OS_VERSION="16.04"
fi

# generate Vagrantfile for the initial box
if [ $OS_VERSION = "16.04" ];then
  vagrant init puppetlabs/ubuntu-16.04-64-nocm --box-version="1.0.0"
else if [ $OS_VERSION = "18.04" ];then
  vagrant init ubuntu/bionic64 --box-version="20181008.0.0"
  else
    echo "Unexpected OS_VERSION specified. Exiting."
    exit 1
  fi
fi

# Make sure "vagrant up" doesn't overwrite the default ssh key when provisioning
# We want this to happen when we actually use the box
sed -i '/config.vm.box.version/a\config.ssh.insert_key = false' Vagrantfile

vagrant up
# copy provisioning script onto the VM and execute
vagrant ssh-config > ssh-config.conf
chmod +x provision${OS_VERSION}.sh
scp -F ssh-config.conf provision${OS_VERSION}.sh default:~/provision.sh
vagrant ssh -c "/bin/bash ./provision.sh ${OS_VERSION}"

# package the box
vagrant package --output testbox.box

# cleanup
vagrant destroy -f
rm -rf ssh-config.conf Vagrantfile .vagrant *cloudimg-console.log

echo "Packaged to `pwd`/testbox.box"
echo """To test the box locally, run 'vagrant box add testbox.box --name boxname', then use it in your Vagrantfile with 'config.vm.box=boxname'"""
