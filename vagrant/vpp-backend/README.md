# Contiv-UI with backend

The repository showcases how js web UI can access kubernetes and contiv API.
Backend acts as a proxy. It exposes two endpoints:

- `http://localhost:9500/k8s/` it forwards requests to kubernetes API
e.g.:
`curl http://localhost:9500/k8s/api/v1/pods` will send `/api/v1/pods` to k8s API server
and forwards the reply back to the client

- `http://localhost:9500/contiv` forwards request to vswitch. By default the requests are
forwarded to a vswitch running on the master node. In order to access a different vswitch
pass its IP in query part. e.g.:
`curl http://localhost:9500/contiv/contiv/v1/ipam?vswitch=10.20.0.10`

## Installation
```
#on the master node
$ git clone <repo>
$ make
$ kubectl apply -f authorization.yaml
$ kubectl apply -f deployment.yaml
```

## Usage

After successful installation, you can access the UI at `http://<master_node_ip>:9500`.

Note: If you use contiv vagrants you might want to forward the UI to your localhost. 
```
$vagrant ssh k8s-master -- -L 9500:localhost:9500
```

## Configuration

The location of configuration file is defined by env var `CONTIV_UI_CONF`.
The example configuration file:
```
    port: 9500
    basicAuth:
      admin: "pass"
    contivPort: 9999
```
