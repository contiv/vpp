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

To build without building debug binaries of VPP, use:
```
./build-all.sh --skip-debug true
# OR
./build-all.sh -s
```

To tag and push the images into [Dockerhub](https://hub.docker.com/u/contivvpp/) execute:
```
./push-all.sh
```

To tag the images without pushing, execute:
```
./push-all.sh --skip-upload true
# OR
./push-all.sh -s
```

To tag and push the devel vswitch image, execute:
```
./push-all.sh --dev-upload true
```

To use the development image for testing with specific version of VPP, see
[DEVIMAGE.md](DEVIMAGE.md).
