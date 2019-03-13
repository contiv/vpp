## ARM64 Cavium Thunderx - Creating VPP startup configuration
This document describes how to create the VPP startup configuration
file located at `/etc/vpp/contiv-vswitch.conf`.

### Hardware interface configuration
#### Multi-NIC configuration
Use lshw to find out the PCI
addresses of all NICs in the system, for example:

```
$ sudo lshw -class network -businfo
Bus info          Device      Class      Description
====================================================
...
pci@0002:01:00.1  enP2p1s0f1  network    Illegal Vendor ID
pci@0002:01:00.2  enP2p1s0f2  network    Illegal Vendor ID
...
```

In the example above, `enP2p1s0f1` would be the primary interface and `enP2p1s0f2` would
be the interface that would be used by VPP. The PCI address of the `enP2p1s0f2`
interface would be `0002:01:00.2`.

Now, make sure that the selected interface is shut down, otherwise VPP
would not grab it:
```
sudo ip link set enP2p1s0f2 down
```
If you want to make this interface inactive permanent across reboots you need to make change
in the file `/etc/network/interfaces`:
```
#https://help.packet.net/technical/networking/layer-2-configurations
#Disabling bond0, putting eth0 to a single VLAN that has an internet gateway, and putting eth1 in a different, private VLAN. ***Currently Disabled

auto lo
iface lo inet loopback

#auto bond0
#iface bond0 inet static
#    address 147.75.98.202
#    netmask 255.255.255.252
#    gateway 147.75.98.201
#    bond-downdelay 200
#    bond-miimon 100
#    bond-mode 4
#    bond-updelay 200
#    bond-xmit_hash_policy layer3+4
#    bond-lacp-rate 1
#    bond-slaves enP2p1s0f1 enP2p1s0f2
#    dns-nameservers 147.75.207.207 147.75.207.208
#iface bond0 inet6 static
#    address 2604:1380:1:5800::1
#    netmask 127
#    gateway 2604:1380:1:5800::
#
#auto bond0:0
#iface bond0:0 inet static
#    address 10.99.164.1
#    netmask 255.255.255.254
#    post-up route add -net 10.0.0.0/8 gw 10.99.164.0
#    post-down route del -net 10.0.0.0/8 gw 10.99.164.0
#
#auto enP2p1s0f1
#iface enP2p1s0f1 inet manual
#    bond-master bond0
#
#auto enP2p1s0f2
#iface enP2p1s0f2 inet manual
#    pre-up sleep 4
#    bond-master bond0

down enP2p1s0f2
iface enP2p1s0f2 inet static
    address 192.168.1.4
    netmask 255.255.255.0

auto enP2p1s0f1
iface enP2p1s0f1 inet static
    address 147.75.98.202
    netmask 255.255.255.252
    gateway 147.75.98.201
```

You need to bind the chosen NIC with proper driver - in our case with VFIO PCI:
for that purpose use utility in DPDK repository - see [DPDK chapter on binding NIC to kernel driver][1]:
```
$ sudo ~/work/dpdk/usertools/dpdk-devbind.py --bind=vfio-pci 0002:01:00.2
$ ~/work/dpdk/usertools/dpdk-devbind.py --status
Network devices using DPDK-compatible driver
============================================
0002:01:00.2 'THUNDERX Network Interface Controller virtual function a034' drv=vfio-pci unused=nicvf

Network devices using kernel driver
===================================
0000:01:10.0 'THUNDERX BGX (Common Ethernet Interface) a026' if= drv=thunder-BGX unused=thunder_bgx,vfio-pci 
0002:01:00.0 'THUNDERX Network Interface Controller a01e' if= drv=thunder-nic unused=nicpf,vfio-pci 
0002:01:00.1 'THUNDERX Network Interface Controller virtual function a034' if=enP2p1s0f1 drv=thunder-nicvf unused=nicvf,vfio-pci *Active*
0002:01:00.3 'THUNDERX Network Interface Controller virtual function a034' if= drv=thunder-nicvf unused=nicvf,vfio-pci 
0002:01:00.4 'THUNDERX Network Interface Controller virtual function a034' if= drv=thunder-nicvf unused=nicvf,vfio-pci 
0002:01:00.5 'THUNDERX Network Interface Controller virtual function a034' if= drv=thunder-nicvf unused=nicvf,vfio-pci 
0002:01:00.6 'THUNDERX Network Interface Controller virtual function a034' if= drv=thunder-nicvf unused=nicvf,vfio-pci 
0002:01:00.7 'THUNDERX Network Interface Controller virtual function a034' if= drv=thunder-nicvf unused=nicvf,vfio-pci 
0002:01:01.0 'THUNDERX Network Interface Controller virtual function a034' if= drv=thunder-nicvf unused=nicvf,vfio-pci 
0002:01:01.1 'THUNDERX Network Interface Controller virtual function a034' if= drv=thunder-nicvf unused=nicvf,vfio-pci 
0002:01:01.2 'THUNDERX Network Interface Controller virtual function a034' if= drv=thunder-nicvf unused=nicvf,vfio-pci 
0002:01:01.3 'THUNDERX Network Interface Controller virtual function a034' if= drv=thunder-nicvf unused=nicvf,vfio-pci 
0002:01:01.4 'THUNDERX Network Interface Controller virtual function a034' if= drv=thunder-nicvf unused=nicvf,vfio-pci 
0002:01:01.5 'THUNDERX Network Interface Controller virtual function a034' if= drv=thunder-nicvf unused=nicvf,vfio-pci 
0002:01:01.6 'THUNDERX Network Interface Controller virtual function a034' if= drv=thunder-nicvf unused=nicvf,vfio-pci 
0002:01:01.7 'THUNDERX Network Interface Controller virtual function a034' if= drv=thunder-nicvf unused=nicvf,vfio-pci 
0002:01:02.0 'THUNDERX Network Interface Controller virtual function a034' if= drv=thunder-nicvf unused=nicvf,vfio-pci 
0002:01:02.1 'THUNDERX Network Interface Controller virtual function a034' if= drv=thunder-nicvf unused=nicvf,vfio-pci 
0002:01:02.2 'THUNDERX Network Interface Controller virtual function a034' if= drv=thunder-nicvf unused=nicvf,vfio-pci 
0002:01:02.3 'THUNDERX Network Interface Controller virtual function a034' if= drv=thunder-nicvf unused=nicvf,vfio-pci 
0002:01:02.4 'THUNDERX Network Interface Controller virtual function a034' if= drv=thunder-nicvf unused=nicvf,vfio-pci 
0002:01:02.5 'THUNDERX Network Interface Controller virtual function a034' if= drv=thunder-nicvf unused=nicvf,vfio-pci 
0002:01:02.6 'THUNDERX Network Interface Controller virtual function a034' if= drv=thunder-nicvf unused=nicvf,vfio-pci 
0002:01:02.7 'THUNDERX Network Interface Controller virtual function a034' if= drv=thunder-nicvf unused=nicvf,vfio-pci 
0002:01:03.0 'THUNDERX Network Interface Controller virtual function a034' if= drv=thunder-nicvf unused=nicvf,vfio-pci 
0006:01:00.0 'THUNDERX Network Interface Controller a01e' if= drv=thunder-nic unused=nicpf,vfio-pci 

Other Network devices
=====================
0002:00:03.0 'THUNDERX Traffic Network Switch a01f' unused=vfio-pci
0006:00:03.0 'THUNDERX Traffic Network Switch a01f' unused=vfio-pci

Crypto devices using DPDK-compatible driver
===========================================
<none>

Crypto devices using kernel driver
==================================
<none>

Other Crypto devices
====================
<none>

Eventdev devices using DPDK-compatible driver
=============================================
<none>

Eventdev devices using kernel driver
====================================
<none>

Other Eventdev devices
======================
<none>

Mempool devices using DPDK-compatible driver
============================================
<none>

Mempool devices using kernel driver
===================================
<none>

Other Mempool devices
=====================
<none>

Compress devices using DPDK-compatible driver
=============================================
<none>

Compress devices using kernel driver
====================================
<none>

Other Compress devices
======================
<none>

```

Setup VFIO permissions for regular users before binding to vfio-pci:
```
$ sudo chmod a+x /dev/vfio
$ sudo chmod 0666 /dev/vfio/*
```
Then you do not need to use sudo command with dpdk-devbind.py utility.


Now, add, or modify the VPP startup config file in `/etc/vpp/contiv-vswitch.conf`
to contain the proper PCI address and the proper kernel module used by chosen NIC:
```
unix {
    nodaemon
    cli-listen /run/vpp/cli.sock
    cli-no-pager
    coredump-size unlimited
    full-coredump
    poll-sleep-usec 100
}
nat {
    endpoint-dependent
    translation hash buckets 1048576
    translation hash memory 268435456
    user hash buckets 1024
    max translations per user 10000
}
acl-plugin {
    use tuple merge 0
}
dpdk {
    dev 0002:01:00.2 
    uio-driver vfio-pci
}
api-trace {
   on
   nitems 5000
}
socksvr {
   default
}
```
If assigning multiple NICs to VPP you will need to include each NIC's PCI address
in the dpdk stanza in `/etc/vpp/contiv-vswitch.conf`.

##### Assigning all NICs to VPP

#### Installing `lshw` on CentOS/RedHat/Fedora
Note: On CentOS/RedHat/Fedora distributions, `lshw` may not be available
by default, install it by
```
sudo yum -y install lshw
```

### Power-saving mode
In regular operation, VPP takes 100% of one CPU core at all times (poll loop).
If high performance and low latency is not required you can "slow-down"
the poll-loop and drastically reduce CPU utilization by adding the following 
stanza to the `unix` section of the VPP startup config file:
```
unix {
    ...
    poll-sleep-usec 100
    ...
}
```
The power-saving mode is especially useful in VM-based development environments 
running on laptops or less powerful servers. 

### VPP API trace
To troubleshoot VPP configuration issues in production environments, it is 
strongly recommended to configure VPP API trace. This is done by adding the
following stanza to the VPP startup config file:
```
api-trace {
    on
    nitems 5000
}
```
You can set the size of the trace buffer with the <nitems> attribute. 

[1]: https://doc.dpdk.org/guides/linux_gsg/linux_drivers.html#linux-gsg-binding-kernel
