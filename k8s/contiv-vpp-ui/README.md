# Contiv VPP UI

Deploy Contiv VPP UI

The deployment consists of the following components:
 * contiv-ui - UI deployment
 * contiv-ui-svc - node port service that allows to access UI from outside of cluster


The `values.yaml` file contains the default values for the
contiv-vpp-ui templates.

## Installing the chart

In order to generate customized deployment file
```console
helm template --name my-release ../contiv-vpp-ui > manifest.yaml
kubectl apply -f manifest.yaml
```

With tiller running in the cluster the chart can be installed with typical helm commands.

To install the chart with the release name `my-release`:

```console
$ helm install --name my-release contiv-vpp-ui
```
## Uninstalling the chart

```console
$ helm delete --purge my-release
```

## Configuration

The following tables lists the configurable parameters of the Contiv-VPP-UI chart and their default values.

Parameter | Description | Default
--------- | ----------- | -------
`uiService.nodePort`|port where the service is exposed| `32500`
`uiService.useHTTPS`|denotes whether secured HTTP should be used to serve UI|`false`
`contiv.APIport`|port where Contiv API is exposed|`9999`
`contiv.CRDport`|port where CRD exposes REST access to netctl|`9090`
`contiv.useHTTPS`|if set to `true` HTTPS will be used to access Contiv API instead of HTTP | `false`
`contiv.validateServerCert`| if Contiv API is accessed via HTTPS decides whether server cert should be validated| `false`
`contiv.useBasicAuth`| if set to true HTTP basic auth credentials will be attached to all requests to Contiv API | `false`
`contiv.basicAuthUser`| username used in HTTP basic-auth for Contiv API  | `user`
`contiv.basicAuthPass`|password used in HTTP basic-auth for Contiv API |`pass`
`image.repository` | ui container image repository | `contivvpp/ui`
`image.tag`| ui container image tag | `latest`
`image.pullPolicy` | ui container image pull policy | `IfNotPresent`
