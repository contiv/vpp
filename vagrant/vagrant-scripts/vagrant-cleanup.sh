#!/bin/bash


if [ -f ../config/init.sh ] ; then
    rm ../config/init.sh
fi
touch ../config/init.sh

if [ -f ../config/cert.sh ] ; then
    rm ../config/cert.sh
fi
touch ../config/cert.sh

vagrant destroy -f

rm -rf ../.vagrant

if [ -f .vagrant-state ] ; then
    rm .vagrant-state
fi

if [ -f ../.vagrant-state ] ; then
    rm ../.vagrant-state
fi
