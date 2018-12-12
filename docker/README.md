## Contiv-VPP Docker Files

This folder contains Docker files + scripts for building Contiv-VPP Docker images
(also available on [Dockerhub](https://hub.docker.com/u/contivvpp/)).

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

To shrink images after build:
note: this will destroy all layers in images
```
./shrink.sh
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
