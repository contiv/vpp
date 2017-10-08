### Contiv CRI 

This CRI (container runtime interface) forwards the requests from kubelet to a Grpc server. The request will then be forwared to docker CRI transparently after injecting a few ENV variables to the container runtime and storing the configuration to a running instance of _etcd_.


To run Contiv CRI, configure kubelet to use remote CRI runtime. Remember to change RUNTIME_ENDPOINT to your own value like: /var/run/{your_runtime}.sock. The value defaults `/var/run/contivshim.sock` when running contiv-cri but you can also change that by using the _--listen_ flag. For additional configuration flags use _contiv-cri -h_. To edit kubelet service configuration: 

```
$ vi /etc/systemd/system/kubelet.service.d/10-kubeadm.conf
Add the following line: 
Environment="KUBELET_EXTRA_ARGS=--fail-swap-on=false --container-runtime=remote --container-runtime-endpoint=/var/run/contivshim.sock"
$ systemctl daemon-reload
```

Now kubelet is ready to use the Contiv CRI runtime, and you can continue with kubeadm init and kubeadm join workflow to deploy Kubernetes cluster
