# Contiv VPP UI

Project page: [https://contivpp.io/](https://contivpp.io)

This project was generated with [Angular CLI](https://github.com/angular/angular-cli) version 7.0.2.

## Quickstart

Deploy UI:
```
kubectl apply -f https://raw.githubusercontent.com/contiv/vpp/master/k8s/contiv-vpp-ui.yaml
```

UI is exposed as nodeport service it can be accessed from web browser at `http://<node-ip>:32500`.

**Note:** Currently, the all UI functionality is supported by three node topology created by [vagrant](../vagrant/vagrant-up) only.

In order to forward the service from vagrant machine run:

```
ssh -F vagrant.conf -L 32500:127.0.0.1:32500 k8s-master
``` 
