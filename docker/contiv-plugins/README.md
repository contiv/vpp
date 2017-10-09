## Contiv Plugins Docker Files

This folder contains Docker files + scripts for building the following
Contiv-VPP plugins Docker images:

 - [CRI](https://hub.docker.com/r/contivvpp/cri/)
 - [CNI](https://hub.docker.com/r/contivvpp/cni/)
 - [KSR](https://hub.docker.com/r/contivvpp/ksr/)

The build is split into two phases:
 - building the binaries in the [dev](dev) container (one for all plugins),
 - extracting the binaries from the [dev](dev) container and building
 much smaller production images with them: [prod/cni](prod/cni), [prod/ksr](prod/ksr).

The containers are based on the Alpine Linux.

To build the images, execute (in this order):
```
cd dev
./build.sh
cd ../prod
./build.sh
```

The result of this procedure is the following list of images:
```
$ sudo docker images | grep contiv-
prod-contiv-ksr          latest       e4401bf902eb        2 minutes ago       52.43 MB
prod-contiv-cni          latest       4b29fd529ef2        2 minutes ago       19.17 MB
dev-contiv-plugins       latest       6bc1d2fbafe7        2 minutes ago       932.6 MB
```