# Custom network configuration

Contiv-VPP defines `CustomConfiguration` [CRD][crd-k8s-docs], which allows to easily customize network configuration of
individual vswitches or even to delegate input configuration into [Ligato][ligato]-based CNFs running on top of the Contiv.
The CRD is defined as a list of configuration items to be applied collectively into a single CNF/vswitch or even across
multiple Ligato agents.

The CRD is completely generic in its design - the configuration of each item is defined simply as a plain YAML-formatted
string. The CRD controller will even accept configuration of objects for which the (protobuf) model is not known at the
time of the Contiv compilation. Even though the controller will not be able to un-marshall the configuration into the
corresponding proto model and thus verify the validity of the input data, it is still able to at least delegate the
configuration data into the target CNF/vswitch through the etcd database. This allows to use the CRD even for
Ligato-based CNFs that implement their own plugins and extend the northbound API of the vanilla agent. CNFs built using
Ligato agent thus integrate with Contiv seamlessly, without the need to define CNF-specific K8s resources and to
implement and run additional CRD controllers.

For a detailed description of the resource specification and its individual fields, please refer to the declaration and
in-code documentation of the `CustomConfiguration` structure defined [here][crd-types].
An example with vswitch-targeted custom bridge domain together with an input configuration for a hypothetical CNF can be
found [here][crd-example].

## Resource Status

Details about the currently applied custom configuration resources can be obtained with:
```
kubectl describe customconfiguration.contivpp.io
```

For a successfully created/updated resource, the status will be shown as follows:
```
Status:
  Metadata:
  Status:  Success
```

For an unsuccessful attempt to apply a `CustomConfiguration` resource, the `Status` will be set to `Failure` and
`Message` will contain the corresponding error message, e.g.:
```
Status:
  Message:  failed to convert updated CustomConfiguration object into key-value data: unknown value "PERMI" for enum vpp.acl.ACL_Rule_Action
  Metadata:
  Status:  Failure
```

Please note that currently the status only informs about whether the CRD controller succeeded in un-marshalling the
resource data and saving the configuration into etcd for the target microservice to read. The microservice could still
fail to apply the configuration, but that can only be learned from its logs (or from whatever feedback mechanism it
provides) at the moment.

[crd-types]: ../../plugins/crd/pkg/apis/contivppio/v1/types.go
[crd-example]: ../../k8s/crd/custom-config.yaml
[ligato]: https://github.com/ligato/vpp-agent/
[crd-k8s-docs]: https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/
