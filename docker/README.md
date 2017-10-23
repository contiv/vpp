## Contiv-VPP Docker Files

This folder contains Docker files + scripts for building Contiv-VPP Docker images
(also available on [Dockerhub](https://hub.docker.com/u/contivvpp/)).
It is organized into two subfolders:

 - [ubuntu-based](ubuntu-based) - contains scripts for building containers based on Ubuntu Linux - VPP vSwitch and CRI,
 - [alpine-based](alpine-based) - contains scripts for building containers based on Alpine Linux: CNI and KSR.

To build all the images, execute:
```
./build-all.sh
```

To tag and push the images into [Dockerhub](https://hub.docker.com/u/contivvpp/) execute:
```
./push-all.sh
```

To tag the images without pushing, execute:
```
./push-all.sh --skip-upload true
```
### Using dev-* containers for code development

The dev-* containers are a full-fledged build & test environment for 
developing Go code for the Contiv VPP Agent, the CRI Shim, or the Contiv CNI
plugin. You can run your builds and unit/integration in a dev-* container 
and your IDE on the host by sharing the source code folder between the host 
and the dev-* container. To do that, map the source folder on your host into
the dev-* container when it's started up as follows:
```bash
   sudo docker run -v <path-to-source-folder-on-host>:/root/go/src/github.com/contiv/vpp/ -it --name <dev-vontainer-name> --rm <dev-container-image> bash
``` 
For example, if the contiv-vpp source code is located in the `go/src/` folder
under your home folder, the command to start the dev-* container will be:
```bash
   sudo docker run -v ~/go/src/github.com/contiv/vpp/:/root/go/src/github.com/contiv/vpp/ -it --name dev-contiv --rm dev-contiv-vswitch bash
```