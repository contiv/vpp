#!/bin/bash

set -euo pipefail

if [ -f ../config/init.sh ] ; then
    rm ../config/init.sh
fi
touch ../config/init.sh

if [ -f ../config/cert.sh ] ; then
    rm ../config/cert.sh
fi
touch ../config/cert.sh

if [ -f ../config/*.tar ] ; then
    rm ../config/*.tar
fi

vagrant destroy -f

rm -rf ../.vagrant

if [ -f .vagrant-state ] ; then
    rm .vagrant-state
fi

if [ -f ../.vagrant-state ] ; then
    rm ../.vagrant-state
fi

if [ -f ../Vagrantfile ] ; then
    rm ../Vagrantfile
fi