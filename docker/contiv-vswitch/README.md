## Contiv vSwitch Docker Files

This folder contains Docker files + scripts for building the
[Contiv-VPP vSwitch](https://hub.docker.com/r/contivvpp/vswitch/) Docker images.

The build is split into two phases:
 - building the binaries in the [dev](dev) container,
 - extracting the binaries from the [dev](dev) container and building
 much smaller [prod](prod) image with them.

The containers are based on the ligato VPP-Agent
[development](https://hub.docker.com/r/ligato/dev-vpp-agent/) and
[production](https://hub.docker.com/r/ligato/vpp-agent/) images that
already contain VPP binaries.

The `FROM` section in both of the [dev](dev/Dockerfile) and [prod](prod/Dockerfile)
Dockerfiles need to be updated when moving to a new version of the ligato VPP agent.

To build the images, execute (in this order):
```
cd dev
./build.sh
cd ../prod
./build.sh
```

The result of this procedure is the following list of images:
```
$ sudo docker images | grep contiv-vswitch
prod-contiv-vswitch      latest         e534d83db5c9        37 minutes ago      498.8 MB
dev-contiv-vswitch       latest         888b4885fff5        37 minutes ago      5.252 GB
```