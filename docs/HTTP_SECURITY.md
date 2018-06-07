# HTTP Security

By default, the access to endpoints (liveness, readiness probe, prometheus stats, ...) served by Contiv-vswitch and
Contiv-ksr is open to anybody. Contiv-vswitch exposes endpoints using port `9999` and contiv-ksr uses `9191`.

To secure access to the endpoints, the SSL/TLS server certificate and basic auth (username password) can be configured.

In Contiv-VPP, this can be done using the Helm charts in [k8s/contiv-vpp folder](../k8s/contiv-vpp).

To generate server certificate the approach described in [ETCD security](ETCD_SECURITY) can be leveraged.

