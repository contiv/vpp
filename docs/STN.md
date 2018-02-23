## STN (Steal The NIC) Deployment

STN is a feature of Contiv-VPP network plugin, that can be used
in case that the k8s node where the plugin is deployed has only
one network interface. Since VPP needs to "own" the interface
that it is controlling, it cannot be longer used for 
forwarding the host traffic.

To use STN feature, make sure you install the STN Daemon on each node
where STN is required. To install it, run as root (not using sudo):
```
bash <(curl -s https://raw.githubusercontent.com/contiv/vpp/master/k8s/stn-install.sh)
```
This installs the STN daemon as a auto-restart docker container, idependent of
the k8s 


Now make sure that VPP startup config contains correct PCI address of the interface,
e.g. `cat cat /etc/vpp/contiv-vswitch.conf`:
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

To check logs of the STN daemon:
```
sudo docker logs contiv-stn
```
