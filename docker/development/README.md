## Contiv-VPP Development Docker Files

These docker files can be used for local development of Contiv-VPP vSwitch.
In order to build the `contivvpp/vswitch` image with a locally-built 
binary of the `contiv-agent`, do:

```
make
cd docker/development
./build.sh
```

This will overwrite your `contivvpp/vswitch:latest` image tag with your 
locally built container image. After that, you can proceed with 
`kubectl apply k8s/contiv-vpp.yaml` to deploy the image.