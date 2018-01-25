#!/bin/sh

sudo /home/mlenco/go/bin/vpp-agent --etcdv3-config=docker/dev_vpp_agent/etcd.conf --kafka-config=docker/dev_vpp_agent/kafka.conf --default-plugins-config=docker/dev_vpp_agent/defaultplugins.conf --linuxplugin-config=docker/dev_vpp_agent/linuxplugin.conf  --logs-config=docker/dev_vpp_agent/logs.conf
