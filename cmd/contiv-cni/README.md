### Contiv CNI Plugin

This plugin forwards the CNI requests to the gRPC server specified in the CNI config file.
The response from gRPC server is then processed back into the standard output of the CNI plugin.

To run the plugin for testing purposes, create the CNI config file `/etc/cni/net.d/10-contiv-cni.conf`:
```
{
	"cniVersion": "0.3.1",
	"type": "contiv-cni",
	"grpcServer": "localhost:9111"
}
```

Given that the `contiv-cni` binary exists in the folder 
`$GOPATH/src/github.com/contiv/contiv-vpp/cmd/contiv-cni`: 

Set `CNI_PATH` environment variable:
```
CNI_PATH=$GOPATH/src/github.com/contiv/contiv-vpp/cmd/contiv-cni
```

Enter the folder with CNI scripts and execute the following:
```
cd vendor/github.com/containernetworking/cni/scripts
sudo CNI_PATH=$CNI_PATH ./priv-net-run.sh ifconfig
```

Expected output in case that the configured gRPC CNI service is running:
```
eth0      Link encap:Ethernet  HWaddr a6:2d:de:17:27:00
          inet addr:10.0.0.1  Bcast:0.0.0.0  Mask:255.255.255.0
          inet6 addr: fe80::a42d:deff:fe17:2700/64 Scope:Link
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:1 errors:0 dropped:0 overruns:0 frame:0
          TX packets:1 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0
          RX bytes:90 (90.0 B)  TX bytes:90 (90.0 B)
```
