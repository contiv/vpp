### K8s State Reflector

To start the reflector you have to have ETCD running first.
if you don't have it installed locally you can use the following docker
image.
```
sudo docker run -p 12379:12379 --name etcd --rm \
    quay.io/coreos/etcd:v3.0.16 /usr/local/bin/etcd \
    -advertise-client-urls http://0.0.0.0:12379 \
    -listen-client-urls http://0.0.0.0:12379
```

It will bring up ETCD listening on port 12379 for client communication.

Start the reflector with:
```
sudo ./contiv-reflector --reflector-config reflector.conf --etcdv3-config etcdv3.conf
```
