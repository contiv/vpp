## Alpine Linux-Based Contiv Docker Files

This folder contains Docker files + scripts for building the following
Contiv-VPP Docker images:

 - [CNI](https://hub.docker.com/r/contivvpp/cni/)
 - [KSR](https://hub.docker.com/r/contivvpp/ksr/)

The build is split into two phases:
 - building the binaries in the [dev](dev) container (one for all plugins),
 - extracting the binaries from the [dev](dev) container and building
 much smaller production images with them: [prod/cni](prod/cni), [prod/ksr](prod/ksr).

The containers are based on the Alpine Linux.

To build the images, execute:
```
./build.sh
```

The result of this procedure is the set of container images similar to this:
```
$ docker images | grep contiv-
prod-contiv-ksr          0.0.1-7-g46d22f7      d0b32d019b9b        About a minute ago   52.43 MB
prod-contiv-cni          0.0.1-7-g46d22f7      5e5bdbe187c5        About a minute ago   19.17 MB
dev-contiv-plugins       0.0.1-7-g46d22f7      f095b72c28f6        About a minute ago   932.7 MB
```

Note that the images are tagged with the current git version (obtained using `git describe --tags`).