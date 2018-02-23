## STN (Steal The NIC) Deployment

STN is a feature of Contiv-VPP network plugin, that can be used
in case that a k8s node where the plugin is deployed has only
one network interface. Since VPP needs to "own" the interface
that it uses for inter-node forwarding, it could not be longer 
used for forwarding the host traffic without STN feature enabled.

To use the STN feature, make sure you install the STN Daemon on each node
where STN is required. To install it, run as root (not using sudo):
```
bash <(curl -s https://raw.githubusercontent.com/contiv/vpp/master/k8s/stn-install.sh)
```
This installs the STN daemon as a auto-restarted docker container, 
which would be completely independent of the k8s cluster infrastructure.


Now make sure that VPP startup config contains correct PCI address of the interface,
e.g. `cat /etc/vpp/contiv-vswitch.conf`:
```
...

dpdk {
    dev 0000:00:08.0
}
...
```

STN feature is disabled by default, it needs to be enabled for each node in the
Contiv-VPP deployment YAML, e.g.:
```
...
    NodeConfig:
    - NodeName: "ubuntu-1"
      StealInterface: "enp0s8"
    - NodeName: "ubuntu-2"
      StealInterface: "enp0s8"
...
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