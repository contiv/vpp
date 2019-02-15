## Creating VPP startup configuration
This document describes how to create the VPP startup configuration
file that should be located located at `/etc/vpp/contiv-vswitch.conf`
on each node in the cluster with Contiv-VPP.


### Hardware interface configuration
#### Single-NIC configuration
You need to configure hardware interfaces for use by VPP. First, you
need to find out the PCI address of the host's network interface. On 
Debian-based distributions, you can use `lshw`:

```
sudo lshw -class network -businfo
Bus info          Device      Class          Description
========================================================
pci@0000:03:00.0  ens160      network        VMXNET3 Ethernet Controller
```

In our case, it would be the `ens3` interface with the PCI address
`0000:00:03.0`.

Now, add or modify the VPP startup config file (`/etc/vpp/contiv-vswitch.conf`)
to contain the proper PCI address:
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
    dev 0000:00:03.0
}
api-trace {
   on
   nitems 5000
}
```


#### Multi-NIC configuration
Similarly to the single-NIC configuration, use lshw to find out the PCI
addresses of all NICs in the system, for example:

```
$ sudo lshw -class network -businfo
Bus info          Device      Class      Description
====================================================
pci@0000:00:03.0  ens3        network    Virtio network device
pci@0000:00:04.0  ens4        network    Virtio network device
```

In the example above, `ens3` would be the primary interface and `ens4` would
be the interface that would be used by VPP. The PCI address of the `ens4`
interface would be `0000:00:04.0`.

Now, make sure that the selected interface is shut down, otherwise VPP
would not grab it:
```
sudo ip link set ens4 down
```

Now, add, or modify the VPP startup config file in `/etc/vpp/contiv-vswitch.conf`
to contain the proper PCI address:
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
    dev 0000:00:04.0
}
api-trace {
   on
   nitems 5000
}
```

If assigning multiple NICs to VPP you will need to include each NIC's PCI address
in the dpdk stanza in `/etc/vpp/contiv-vswitch.conf`.


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
    nitems 500
}
```
You can set the size of the trace buffer with the <nitems> attribute. 
