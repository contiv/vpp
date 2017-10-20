## Ubuntu Linux-Based Contiv Docker Files

This folder contains Docker files + scripts for building the following
Contiv-VPP Docker images:

 - [vSwitch](https://hub.docker.com/r/contivvpp/vswitch/)
 - [CRI](https://hub.docker.com/r/contivvpp/cri/)

The build is split into two phases:
 - building the binaries in the [dev](dev) container,
 - extracting the binaries from the [dev](dev) container and building
 much smaller [prod](prod) image with them.

The containers are based on the ligato VPP-Agent
[development](https://hub.docker.com/r/ligato/dev-vpp-agent/) and
[production](https://hub.docker.com/r/ligato/vpp-agent/) images that
already contain VPP binaries.

The `FROM` section in both of the [dev](dev/Dockerfile) and [vswitch prod](prod/vswitch/Dockerfile)
Dockerfiles need to be updated when moving to a new version of the ligato VPP agent.

To build the images, execute:
```
./build.sh
```

The result of this procedure is the set of container images similar to this:
```
$ sudo docker images | grep contiv-vswitch
prod-contiv-vswitch      0.0.1-7-g46d22f7        a18a66f3091f        20 seconds ago      473.9 MB
dev-contiv-vswitch       0.0.1-7-g46d22f7        b494c8622263        23 seconds ago      5.252 GB
```

Note that the images are tagged with the current git version (obtained using `git describe --tags`).