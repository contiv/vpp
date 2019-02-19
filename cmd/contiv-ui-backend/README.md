# Contivvpp-UI backend

Backend acts as a proxy. It exposes three endpoints:
- `/api/k8s/<kubernetes-api-path>` forwards requests to kubernetes API
e.g.:
    ```
    curl http://localhost:32500/api/k8s/api/v1/pods
    ```
  will send `/api/v1/pods` to k8s API server and forwards the reply back to the client.
- `/api/contiv/<contiv-api-path>?vswitch=<node_ip>` forwards requests to
a given vswitch e.g.:
    ```
    curl http://localhost:32500/api/contiv/contiv/v1/ipam?vswitch=10.20.0.10
    ```
    will send `contiv/v1/ipam` to vswitch running at IP `10.20.0.10`
- `/api/netctl?master=<master_ip>` executes contiv-netctl command with arguments provided
  in request body in format of JSON array. e.g.:
   ```
   curl -X POST -H "Content-Type: application/json" localhost:32500/api/netctl?master=10.0.2.15 -d '["nodes"]'
   ```
   will execute command `contiv-netctl nodes`
