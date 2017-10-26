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
`kubectl apply -f k8s/contiv-vpp.yaml` to deploy the image.

### Using the development container for builds

The development container (dev-contiv-vswitch) is a full-fledged build & test
environment for developing Contiv VPP Agent Go code. If you do not have the 
build environment/tools installed on your host, you can use the development 
container to run your builds. You can run your IDE on the host by sharing the
source code folder between the host and the development container. To do that,
map the source folder on your host into the development container when you 
start it up as follows:
```bash
sudo docker run -v <path-to-source-folder-on-host>:/root/go/src/github.com/contiv/vpp/ -it --name <dev-vontainer-name> --rm <dev-container-image> bash
``` 
For example, if the contiv-vpp source code is located in the `src/` folder
under your Go path root folder on your host, the command to start the
development container will be:
```
sudo docker run -v $GOPATH/src/github.com/contiv/vpp/:/root/go/src/github.com/contiv/vpp/ -it --name dev-contiv --rm dev-contiv-vswitch bash
```

You can either download the development container from Dockerhub, or build it 
locally on your host from the contiv/vpp/docker directory as described [here][1].

[1]: https://github.com/contiv/vpp/blob/master/docker/README.md
