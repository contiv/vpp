# How to add new CRD for Contiv-VPP

This is a step-by-step guide for developers on how to add new [Custom Resource (CRD)][crd-k8s-docs] into Contiv-VPP.

1. Add definition of your CRD into `plugins/crd/pkg/apis/contivppio/v1/types.go`. The definition should consist of three
   structures - the resource top-level definition grouping metadata and the specification, the resource specification
   and a structure representing list of your resources.
   Here is the template to follow (notice the `genclient` and `k8s` tags):
   ```
   // <Your-Resource> is used to ...
   // +genclient
   // +genclient:noStatus
   // +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
   type <Your-Resource> struct {
   	// TypeMeta is the metadata for the resource, like kind and apiversion
   	meta_v1.TypeMeta `json:",inline"`
   	// ObjectMeta contains the metadata for the particular object
   	meta_v1.ObjectMeta `json:"metadata,omitempty"`
   	// Spec is the specification of the resource
   	Spec <Your-Resource>Spec `json:"spec"`
   }
   
   // <Your-Resource>Spec is the specification for ...
   type <Your-Resource>Spec struct {
   	  // TODO: define the resource fields here
   }
  
   // <Your-Resource>List is a list of ...
   // +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object
   type <Your-Resource>List struct {
   	meta_v1.TypeMeta `json:",inline"`
   	meta_v1.ListMeta `json:"metadata"`
   
   	Items []<Your-Resource> `json:"items"`
   }
   ```
   The resource will be available under the `contivppio` group (i.e. `apiVersion: contivpp.io/v1`). Alternatively,
   you could create a new group under `plugins/crd/pkg/apis/` for your CRD(s), but this is not recommended.
   
2. Generate ClientSet, Informers and Listers for you CRD.
   From the Contiv-VPP top-level directory, run: 
   ```
   $ cd $GOPATH/src/github.com/contiv/vpp
   $ plugins/crd/scripts/update-codegen.sh
   ```
   
3. Add your CRD into the list of known types.
   Append empty instances of `<Your-Resource>` and `<Your-Resource>List` structures into `scheme.AddKnownTypes()` inside
   the method `addKnownTypes()` implemented for `contivpp` CRD group in `plugins/crd/pkg/apis/contivppio/v1/register.go`.

4. Implement Handler for you CRD (i.e. define what to do when an instance of your CRD is Created/Updated/Deleted).
   In Contiv-VPP all CRDs with the exception of Telemetry are just mirrored into the `etcd` datastore by `contiv-crd`
   (process running the CRD controllers), from where they are processed by `contiv-vswitch` through `DBResync` and
    `KubeStateChange` events - more information about these events can be found [here][controller-events].
    A generic CRD handler mirroring CRD state into `etcd` is available in `plugins/crd/handler/kvdbreflector`.
    In order to "inherit" from the generic `kvdbreflector`, a `Handler` interface (defined [here][kvdbreflector])
    has to be implemented (under `plugins/crd/handler/<your-resource>`) and passed to the reflector as `Deps.Handler`.
    Basically, the handler should "teach" the reflector how to convert a CRD structure instance (defined in 1.)
    into a corresponding proto message and where - i.e. under what key - to store it into the DB. The proto model
    should be defined under `plugins/crd/handler/<your-resource>/model`.

5. Create controller for your resource.
   Use the following code template (replace `<your-resource>`) to construct and initialize resource controller inside
   the `Init` method of the crd plugin (`plugins/crd/plugin_impl_crd.go`):
```
import "github.com/contiv/vpp/plugins/crd/handler/<your-resource>"

type Plugin struct {
    // ...
    <your-resource>Controller        *controller.CrdController
}

func (p *Plugin) Init() error {
     // ...
   
   	<your-resource>Informer := sharedFactory.Contivpp().V1().<your-resource>().Informer()
   	p.<your-resource>Controller = &controller.CrdController{
   		Deps: controller.Deps{
   			Log:       p.Log.NewLogger("-<your-resource>Controller"),
   			APIClient: apiclientset,
   			Informer:  <your-resource>Informer,
   			EventHandler: &kvdbreflector.KvdbReflector{
   				Deps: kvdbreflector.Deps{
   					Log:      p.Log.NewLogger("-<your-resource>Handler"),
   					Publish:  p.Publish,
   					Informer: <your-resource>Informer,
   					Handler:  &<your-resource>.Handler{},
   				},
   			},
   		},
   		Spec: controller.CrdSpec{
   			TypeName:  reflect.TypeOf(v1.<your-resource>{}).Name(),
   			Group:     contivppio.GroupName,
   			Version:   "v1",
   			Plural:    "<your-resource>s",
   		},
   	}
   
   	// Init and run the controllers
   	// ...
   	p.<your-resource>Controller.Init()
   
   	if p.verbose {
        // ...
   		p.<your-resource>Controller.Log.SetLevel(logging.DebugLevel)
   	}
   
   	// ...
}

func (p *Plugin) AfterInit() error {
	go func() {
        // ...
		go p.<your-resource>Controller.Run(p.ctx.Done())
	}()

	return nil
}
```

6. For `etcd`-mirrored CRD that should be processed by `contiv-vswitch`, define your resource in the [dbresources] package.
   This will make the updates about your resource instance included in the `KubeStateChange` and a full snapshot of created
   instances will be available in the `DBResync` event.

7. Don't forget to rebuild both `contivvpp/vswitch` and `contivvpp/crd` images.

[crd-k8s-docs]: https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/
[controller-events]: CORE_PLUGINS.md#events
[kvdbreflector]: ../../plugins/crd/handler/kvdbreflector/kvdb_reflector.go
[db-resources]: https://github.com/contiv/vpp/tree/master/dbresources