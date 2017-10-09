## Contiv-VPP Docker Files

This folder contains Docker files + scripts for building Contiv-VPP Docker images
(also available on [Dockerhub](https://hub.docker.com/u/contivvpp/)).
It is organized into two subfolders:

 - [contiv-vswitch](contiv-vswitch) - contains scripts for building VPP vSwitch and its management agent,
 - [contiv-plugins](contiv-plugins) - contains scripts for building the rest of Contiv-VPP components: CNI, CRI, KSR.

To build all the images, execute:
```
./build-all.sh
```

To tag and push the images into [Dockerhub](https://hub.docker.com/u/contivvpp/) execute:
```
./push-all.sh
```
