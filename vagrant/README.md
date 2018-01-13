## Contiv-VPP Vagrant Installation

This folder contains the Vagrantfile to create a single or multi-node 
Kubernetes cluster using Contiv-VPP as a Network Plugin. 

It is organized into two subfolders:

 - (config) - contains the files needed to share cluster information, used during the provisioning stage (master IP address, Certificates, hash-keys). Editing is not recommended!
 - (vagrant-scripts) - contains scripts for creating, destroying, rebooting and shuting down the VMs that host the K8s cluster.

To define the cluster's size edit the value K8S_NODES found in vagrant-scripts/vagrant-up.sh script:
```
export K8S_NODES=0, for a single-node setup
export K8S_NODES=1, for a two-node setup
```

To create and run the cluster run vagrant-up.sh script, located inside vagrant-scripts folder:
```
cd vagrant-scripts/
./vagrant-up.sh
```

To destroy and clean-up the cluster run vagrant-cleanup.sh script, located inside vagrant-scripts folder:
```
cd vagrant-scripts/
./vagrant-cleanup.sh
```

To shutdown the cluster run vagrant-shutdown.sh script, located inside vagrant-scripts folder:
```
cd vagrant-scripts/
./vagrant-shutdown.sh
```

To reboot the cluster run vagrant-reload.sh script, located inside vagrant-scripts folder:
```
cd vagrant-scripts/
./vagrant-reload.sh
```

From a suspended state, or after a reboot of the host machine, cluster can be brought up by running the vagrant-up.sh script.
