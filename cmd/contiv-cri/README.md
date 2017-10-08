### Contiv CRI 

This CRI (container runtime interface) forwards the requests from kubelet to a Grpc server. 

The requests will then be forwarded to docker CRI transparently after injecting a few ENV variables to the container runtime and storing the configuration to a running instance of _etcd_.

To run Contiv CRI, configure kubelet to use remote CRI runtime. 
Remember to change RUNTIME_ENDPOINT to your own value like: /var/run/{your_runtime}.sock. 

The value defaults to `/var/run/contivshim.sock` but you can be changed to a different value using the **--listen**flag. 
For additional configuration flags use **contiv-cri -h**. 

To edit kubelet service configuration: 

```
$ vi /etc/systemd/system/kubelet.service.d/10-kubeadm.conf
```
Add the following line: 
```
Environment="KUBELET_EXTRA_ARGS=--fail-swap-on=false --container-runtime=remote --container-runtime-endpoint=/var/run/contivshim.sock"
```
And finally restart the daemon:
```
$ systemctl daemon-reload
```

Now kubelet is ready to use the Contiv CRI runtime, and you can continue with kubeadm init and kubeadm join workflow to deploy Kubernetes cluster
