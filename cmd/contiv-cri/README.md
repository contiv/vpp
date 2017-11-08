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

VCL namespacing is configured by the following boolean labels.
```
ldpreload
proxytcp
proxyudp
scopeglobal
scopelocal
```

Example yaml files
iperf.server
```yaml
apiVersion: v1
kind: Service
metadata:
  name: server-iperf
  labels:
    app: test-server-iperf
spec:
  ports:
  - name: test-server-iperf
    port: 5201
  selector:
    app: test-server-iperf
---
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: test-server-iperf
spec:
  replicas: 1
  template:
    metadata:
      labels:
        app: test-server-iperf
        ldpreload: "true"
        scopeglobal: "true"
    spec:
      containers:
      - image: networkstatic/iperf3
        imagePullPolicy: IfNotPresent
        name: server-iperf
        ports:
        - containerPort: 5201
        command: ["iperf3"]
        args: ["-V4d", "-s"]
        securityContext:
          privileged: true
```

iperf.client
```yaml
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: test-client
spec:
  replicas: 1
  template:
    metadata:
      labels:
        app: test-client
        ldpreload: "true"
        scopeglobal: "true"
    spec:
      containers:
      - image: networkstatic/iperf3
        imagePullPolicy: IfNotPresent
        name: client
        command: ["bash"]
        args: ["-c", "while true; do sleep 30; done;"]
        securityContext:
          privileged: true
```

```
kubectl get pods -o wide
```

```
kubectl exec -it iperf-client-xx89s -- iperf3 -V4d -c 10.1.135.5
```