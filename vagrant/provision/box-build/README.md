# Custom boxes

This directory contains scripts which create custom boxes for CI testing. They come with
preinstalled docker, kubernetes and kubeadm images pulled.

Usage:
```
export OS_VERSION="18.04"
./box-build.sh
```
This will build the box from ubuntu/bionic64 and package it into "testbox.box". The scripts
will need to be modified to support anything other than the Ubuntu 16.04 and 18.04 boxes we use.

To test the box locally you can run:
```
vagrant box add testbox.box --name somename
```
Then use it in a Vagrantfile like this:
```
config.vm.box = "somename"
```
Once you're happy with the box, rename the file and upload it to vagrantcloud.com
Follow the instructions provided there for how to start using it.
