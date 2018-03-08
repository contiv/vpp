### Setting up a node with a single NIC

#### Installing the STN daemon
The STN Daemon must be installed on every node in the cluster that has only 
one NIC. The STN daemon installation should be performed before deployment 
of the Contiv-VPP plugin.

Run as root (not using sudo):
```
bash <(curl -s https://raw.githubusercontent.com/contiv/vpp/master/k8s/stn-install.sh)
```

To check the logs of the STN daemon, use `docker logs` command:
```
sudo docker logs contiv-stn
```

The expected logs would look like the following excerpt:
```
2018/02/23 10:08:34 Starting the STN GRPC server at port 50051
2018/02/23 10:09:20 GRPC StealInterface request: interface_name:"enp0s8" 
2018/02/23 10:09:21 Returning GRPC data: pci_address:"0000:00:08.0" ip_addresses:"192.168.56.101/24" routes:<destination_subnet:"192.168.56.0/24" > 
2018/02/23 10:09:22 GRPC StolenInterfaceInfo request: interface_name:"enp0s8" 
2018/02/23 10:09:22 Returning GRPC data: pci_address:"0000:00:08.0" ip_addresses:"192.168.56.101/24" routes:<destination_subnet:"192.168.56.0/24" > 
2018/02/23 10:09:31 Starting periodic check of status of the contiv-agent
2018/02/23 10:36:18 Unable to connect to health check probe at port 9999, reverting the interfaces
2018/02/23 10:36:18 Reverting interface enp0s8
2018/02/23 10:36:18 Unbinding 0000:00:08.0 from its current driver
2018/02/23 10:36:18 Binding 0000:00:08.0 to driver e1000
2018/02/23 10:36:18 IP link lookup attempt 1 failed, retry
2018/02/23 10:36:18 Setting interface enp0s8 (idx 82) to UP state
2018/02/23 10:36:18 Adding IP address 192.168.56.101/24 enp0s8 to interface enp0s8 (idx 82)
2018/02/23 10:36:18 enp0s8: IP 192.168.56.101 already exists, skipping
2018/02/23 10:36:18 Adding route to 192.168.56.0/24 for interface enp0s8
2018/02/23 10:36:18 enp0s8: route to 192.168.56.0 already exists, skipping
```

For more details, please read the Go documentation for 
[contiv-stn](../cmd/contiv-stn/doc.go)
and
[contiv-init](../cmd/contiv-init/doc.go).

#### Creating the VPP interface configuration
First, you need to find out the PCI address of the host's network interface. that
On a Debian-based distributions, you can use `lshw`:

```
$ sudo lshw -class network -businfo
Bus info          Device      Class      Description
====================================================
pci@0000:00:03.0  ens3        network    Virtio network device
```

In our case, it would be the `ens3` interface with the PCI address
`0000:00:03.0`.


Now, add, or modify the VPP startup config file in `/etc/vpp/contiv-vswitch.conf`
to contain the proper PCI address:
```
unix {
    nodaemon
    cli-listen /run/vpp/cli.sock
    cli-no-pager
}
dpdk {
    dev 0000:00:03.0
}
```

#### Configuring STN in Contiv-vpp K8s deployment files
The STN feature is disabled by default. It needs to be enabled either globally,
or individually for every node in the cluster. 

##### Global configuration:
Global configuration is used in homogeneous environments where all nodes in 
a given cluster have the same hardware configuration, for example only a single
Network Adapter. To enable the STN feature globally, put the following stanza
into the `contiv-vpp.yaml` deployment file:

Note that the Network Adapters on different nodes do not need to be of the 
same type. You still need to create the respective vswitch configurations on
every node in the cluster, as shown [here](#Creating-the-VPP-interface-configuration).

##### Individual configuration:
Individual configuration is used in heterogeneous environments where each node
in a given cluster may be configured differently. To enable the STN feature 
for a specific node in the cluster, put the following stanza into its Node
Configuration:
```
...
    NodeConfig:
    - NodeName: "ubuntu-1"
      StealInterface: "enp0s8"
    - NodeName: "ubuntu-2"
      StealInterface: "enp0s8"
...
``` 
Note that you still have to create the vswitch configuration on the node as
shown [here](#Creating-the-VPP-interface-configuration).



#### Uninstalling the STN daemon
