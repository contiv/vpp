#!/bin/bash

rm ../config/init.sh
touch ../config/init.sh

rm ../config/cert.sh
touch ../config/cert.sh

vagrant destroy -f
rm -rf ../.vagrant
rm .vagrant-state