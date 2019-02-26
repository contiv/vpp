# Contiv VPP UI

Demo: [video at contivpp.io](https://contivpp.io/demo/contivpp-io-demo-ui/)

This project was generated with [Angular CLI](https://github.com/angular/angular-cli) version 7.0.2.

## Quickstart

Deploy UI:
```
kubectl apply -f https://raw.githubusercontent.com/contiv/vpp/master/k8s/contiv-vpp-ui.yaml
```

UI is exposed as nodeport service it can be accessed from web browser at `http://<node-ip>:32500`.

In order to forward the service from vagrant machine run:

```
vagrant ssh-config > vagrant.conf
ssh -F vagrant.conf -L 32500:127.0.0.1:32500 k8s-master
```

## Configuration

Default UI deployment assumes that Contiv API is exposed via HTTP without additional security features.
If that is not the case follow [README](../k8s/contiv-vpp-ui/README.md) and generate your customized
deployment yaml file using helm.
