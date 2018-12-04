#!/bin/sh

# master port forwarding
VBoxManage controlvm $(VBoxManage list vms | grep k8s-master | cut -d'"' -f 2) natpf1 "k8s-api,tcp,127.0.0.1,8080,127.0.0.1,8080"
VBoxManage controlvm $(VBoxManage list vms | grep k8s-master | cut -d'"' -f 2) natpf1 "vpp-api,tcp,127.0.0.1,9999,127.0.0.1,9999"

# worker1 port forwarding
VBoxManage controlvm $(VBoxManage list vms | grep k8s-worker1 | cut -d'"' -f 2) natpf1 "k8s-api,tcp,127.0.0.1,8081,127.0.0.1,8080"
VBoxManage controlvm $(VBoxManage list vms | grep k8s-worker1 | cut -d'"' -f 2) natpf1 "vpp-api,tcp,127.0.0.1,9991,127.0.0.1,9999"

# worker2 port forwarding
VBoxManage controlvm $(VBoxManage list vms | grep k8s-worker2 | cut -d'"' -f 2) natpf1 "k8s-api,tcp,127.0.0.1,8082,127.0.0.1,8080"
VBoxManage controlvm $(VBoxManage list vms | grep k8s-worker2 | cut -d'"' -f 2) natpf1 "vpp-api,tcp,127.0.0.1,9992,127.0.0.1,9999"
