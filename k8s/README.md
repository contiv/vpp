## Contiv-VPP Kubernetes Deployment Files

This folder contains a set of files that can be used to deploy Contiv-VPP
network plugin on Kubernetes.

#### contiv-vpp.yaml
The main deployment file that can be used to deploy Contiv-VPP network plugin using `kubeadm`:
```
# deploy
kubectl apply -f contiv-vpp.yaml

# undeploy
kubectl delete -f contiv-vpp.yaml
```
Optionaly you can edit `contiv-vpp.yaml` to deploy the dev-contiv-vswitch image, built
in local environment with `../docker/build-all.sh`.
```
sed -i "s@image: contivvpp/vswitch@image: dev-contiv-vswitch:<your image version>@g" ./contiv-vpp.yaml
```


#### cri-install.sh
Contiv-VPP CRI Shim installer / uninstaller, that can be used as follows:
```
# install
./cri-install.sh

# uninstall
./cri-install.sh --uninstall
```

#### pull-images.sh
This script can be used to pull the newest version of the `:latest` tag of all Docker images 
that Contiv-VPP plugin uses. This may be needed in case that you have already used Contiv-VPP plugin
on the host before and have the old (outdated) versions of docker images stored locally.
