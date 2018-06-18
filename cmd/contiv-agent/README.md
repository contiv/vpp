### Contiv agent

Contiv agent manages vpp in order to setup container networking on a k8s node.

To start the agent run:

```
sudo cmd/contiv-agent/contiv-agent --grpc-port 9111
```

Optionally, you can add argument defining connection to etcd. If connection to etcd
is defined the agent persists the configuration into it.
```
--etcd-config vendor/github.com/ligato/vpp-agent/docker/dev_vpp_agent/etcd.conf
```

Currently, the containers are connected to vswitch using vEth pairs.
