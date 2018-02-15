# Contiv VPP

Deploy Contiv VPP networking

The deployment consists of the following components:
 * contiv-etcd - deployed on the master node
 * contiv-vswitch - deployed on each node
 * contiv-ksr - deployed on the master node

The `values.yaml` file contains the default values for the
contiv-vpp templates.

## Installing the chart

To install the chart with the release name `my-release`:

```console
$ helm install --name my-release contiv-vpp
```
## Uninstalling the chart

```console
$ helm delete --purge my-release
```


## Configuration

The following tables lists the configurable parameters of the Contiv-VPP chart and their default values.

Parameter | Description | Default
--------- | ----------- | -------
