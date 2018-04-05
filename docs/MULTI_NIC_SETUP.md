### Setting up a node with multiple NICs

#### Creating the VPP interface configuration
You need to find out the PCI address of the network interface that you want
to be used by VPP. On Debian-based distributions, you can use `lshw`:

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
}
dpdk {
    dev 0000:00:04.0
}
```

#### Assigning multiple NICs to VPP
On a multi-NIC node, you can assign multiple NICs from the kernel
for use by VPP. First, you need to install the STN daemon, as described 
[here][1]. 

You also need to configure the NICs in the VPP startup config file
in `/etc/vpp/contiv-vswitch.conf`. For example, to use both the primary and
secondary NIC in a two-NIC node, your VPP startup config file would look
something like this:

```
unix {
    nodaemon
    cli-listen /run/vpp/cli.sock
    cli-no-pager
}
dpdk {
    dev 0000:00:03.0
    dev 0000:00:04.0
}
```

Finally, for each interface owned by Linux, you need to provide individual
configuration for each interface used by VPP in the Node Configuration for the
node in the `contiv-vpp.yaml`. For example, if both `ens3` and `ens4` are
known to Linux, you put the following stanza into the node's NodeConfig:
```
...
    NodeConfig:
    - NodeName: "ubuntu-1"
      StealInterface: "ens3"
      StealInterface: "ens4"
...
``` 

If only `ens3` is known to Linux, you only put a line for `ens3' into the 
above NodeConfig.

[1]: SINGLE_NIC_SETUP.md
