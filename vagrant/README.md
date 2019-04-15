## Contiv-VPP Vagrant Installation

### Prerequisites:
- Vagrant 2.0.1 or later
- Hypervisors:
  - VirtualBox 5.2.8 or later 
  - VMWare Fusion 10.1.0 or later or VmWare Workstation 14
    - For use VmWare Fusion you will need the Vagrant VmWare Fusion plugin (https://www.vagrantup.com/vmware/index.html)
- Laptop or server with at least 4 CPU cores and 16 Gig of RAM    

### Creating / shutting down / destroying the cluster:
This folder contains the Vagrant file to create a single or multi-node 
Kubernetes cluster using Contiv-VPP as a Network Plugin. 

It is recommended to use the following provided scripts for managing the cluster:
 
 * [`vagrant-up`](vagrant-up) to start a default cluster with 1 master and 1 worker,
 * [`vagrant-start`](vagrant-up) to start start a cluster using an interactive script asking for options,
 * [`vagrant-cleanup`](vagrant-cleanup) to destroy the cluster.

The following environment variables can be used to customize the cluster options 
(defaults are defined and can be also customized in the [defaults](defaults) file):

Environment variable | Description | Default
--------- | ----------- | -------
`K8S_NODE_OS` | OS to be used for cluster node. Vagrantfile currently supports only `ubuntu` | `ubuntu`
`K8S_NODE_OS_RELEASE` | Version of the OS to be used for cluster nodes `16.04` or `18.04`| `16.04`
`K8S_MASTER_CPUS` | Number of CPUs to be allocated for a master node | `4`
`K8S_NODE_CPUS` | Number of CPUs to be allocated for a worker node | `4`
`K8S_MASTER_MEMORY` | Memory size for master node | `4096`
`K8S_NODE_MEMORY` | Memory size for worker nodes | `4096`
`K8S_NODES` | Number of worker nodes (except from the master) | `1`
`K8S_MASTER_NODES` | Number of master nodes (Beware: multimaster feature is experimental doesn't work for all option combination) | `1`
`K8S_VERSION` | Kubernetes version to be installed | `1.12.3`
`K8S_DEPLOYMENT_SCENARIO` | Contiv deployment scenario to be used: `nostn` (default) or [`stn`](../docs/setup/SINGLE_NIC_SETUP.md) or [`calico-vpp`](calico-vpp/README.md) | `nostn`
`K8S_DEPLOYMENT_ENV` | Contiv deployment environment to be used: `prod` (production) or `dev` (development) | `prod`
`CONTIV_IMAGE_TAG` | Docker image tag denoting contiv/vpp version to be installed | `latest`
`CRD_DISABLED` | If set to `true` nodeconfig must be set in contiv deployment file. Otherwise it is configure using crd. | `true`
`HELM_EXTRA_OPTS` | Allows to pass arbitrary helm option see [available parameters](../k8s/contiv-vpp)| `""`

If you want to customize the default behavior via environment variables, export the 
variables that need to be overridden and execute `./vagrant-up`, e.g.:
```bash
cd vagrant
export K8S_NODE_OS_RELEASE=18.04
export K8S_NODES=2
./vagrant-up
```

You can use the interactive `vagrant-start` script to customize the default behavior, alternatively.
The `vagrant-start` script prompts the user to select the number of worker nodes of the kubernetes cluster.
Zero (0) worker nodes mean that a single-node cluster (with one kubernetes master node) will be deployed.
Next, the user is prompted to select either the *production environment* or the *development environment*.
Instructions on how to build the development contiv/vpp-vswitch image can be found in the
next paragraph. The last option asks the user to select between *Without StealTheNIC* and *With StealTheNIC*
Given option With *StealTheNIC* the plugin will "steal" interfaces owned by Linux and use their configuration in VPP.

For the production environment run:
```bash
$ cd vagrant/
$ ./vagrant-start
Please provide the number of workers for the Kubernetes cluster (0-50) or enter [Q/q] to exit: 1

Please choose Kubernetes environment: 
1) Production
2) Development
3) Quit
--> 1
You chose Production environment

Please choose deployment scenario: 
1) Without StealTheNIC	3) Calico		5) Quit
2) With StealTheNIC	4) Calico-VPP
--> 1
You chose deployment without StealTheNIC

Creating a production environment, without STN and 1 worker node(s)

Creating VirtualBox DHCP server...
...
```

For the development environment run:
```bash
$ cd vagrant/
$ ./vagrant-start
Please provide the number of workers for the Kubernetes cluster (0-50) or enter [Q/q] to exit: 1

Please choose Kubernetes environment:
1) Production
2) Development
3) Quit
--> 2
You chose Development environment

Please choose deployment scenario: 
1) Without StealTheNIC	3) Calico		5) Quit
2) With StealTheNIC	4) Calico-VPP
--> 1
You chose deployment without StealTheNIC

Creating a development environment, without STN and 1 worker node(s)
...
```

To destroy and clean-up the cluster, run the `vagrant-cleanup` script:
```bash
cd vagrant/
./vagrant-cleanup
```

To shutdown the cluster run the `vagrant-shutdown` script:
```
cd vagrant/
./vagrant-shutdown
```

To reboot the cluster run the `vagrant-reload` script
```
cd vagrant/
./vagrant-reload
```

From a suspended state, or after a reboot of the host machine, the cluster
can be brought up by running the `vagrant-up` script.


### Building and deploying the contivvpp/dev-vswitch image (optional)
If you chose the deployment with the development environment follow the
instructions to build a modified contivvpp/vswitch image.

1. Make sure changes in the code have been saved. From the k8s-master node, 
   build the new contivvpp/vswitch image (run as sudo)

```
vagrant ssh k8s-master
cd /vagrant/config
sudo ./save-dev-image
```

2. The newly built contivvpp/vswitch image is now tagged as latest. Verify 
with `sudo docker images`; contivvpp/vswitch should have been created a few
seconds ago. The new image with all the changes must become available to all
the nodes in the K8s cluster. To do so, load the docker image into the running
worker nodes (run as sudo).

```
vagrant ssh k8s-worker1
cd /vagrant/config
sudo ./load-dev-image
```

Verify with `sudo docker images`; old contivvpp/vswitch should now be tagged as
`<none>` and the latest tagged  contivvpp/vswitch should have been created a
few seconds ago.


### Exploring the cluster:
Once the cluster is up, log into the master:
```
$ cd vagrant
$ vagrant ssh k8s-master

Welcome to Ubuntu 16.04 LTS (GNU/Linux 4.4.0-21-generic x86_64)

 * Documentation:  https://help.ubuntu.com/
vagrant@k8s-master:~$ 
```
Verify the Kubernetes/Contiv-VPP installation. First, verify the nodes in the cluster:

```
vagrant@k8s-master:~$ kubectl get nodes -o wide

NAME          STATUS   ROLES    AGE     VERSION   INTERNAL-IP   EXTERNAL-IP   OS-IMAGE           KERNEL-VERSION     CONTAINER-RUNTIME
k8s-master    Ready    master   6m46s   v1.12.3   10.20.0.2     <none>        Ubuntu 16.04 LTS   4.4.0-21-generic   docker://18.3.0
k8s-worker1   Ready    <none>   4m56s   v1.12.3   10.20.0.10    <none>        Ubuntu 16.04 LTS   4.4.0-21-generic   docker://18.3.0
```

Next, verify that all pods are running correctly:

```
vagrant@k8s-master:~$ kubectl get pods -n kube-system -o wide

NAME                                 READY   STATUS    RESTARTS   AGE     IP           NODE          NOMINATED NODE
contiv-crd-qgg6g                     1/1     Running   0          6m52s   10.20.0.2    k8s-master    <none>
contiv-etcd-0                        1/1     Running   0          6m52s   10.20.0.2    k8s-master    <none>
contiv-ksr-55g4g                     1/1     Running   0          6m52s   10.20.0.2    k8s-master    <none>
contiv-vswitch-6l5s4                 1/1     Running   0          6m52s   10.20.0.2    k8s-master    <none>
contiv-vswitch-wz42q                 1/1     Running   0          5m20s   10.20.0.10   k8s-worker1   <none>
coredns-576cbf47c7-7ct48             1/1     Running   0          6m52s   10.1.1.2     k8s-master    <none>
coredns-576cbf47c7-bt8qs             1/1     Running   0          6m52s   10.1.1.3     k8s-master    <none>
etcd-k8s-master                      1/1     Running   0          6m16s   10.20.0.2    k8s-master    <none>
kube-apiserver-k8s-master            1/1     Running   0          5m54s   10.20.0.2    k8s-master    <none>
kube-controller-manager-k8s-master   1/1     Running   0          5m55s   10.20.0.2    k8s-master    <none>
kube-proxy-kqpk6                     1/1     Running   0          5m20s   10.20.0.10   k8s-worker1   <none>
kube-proxy-swfnk                     1/1     Running   0          6m52s   10.20.0.2    k8s-master    <none>
kube-scheduler-k8s-master            1/1     Running   0          6m2s    10.20.0.2    k8s-master    <none>
```

Check VPP and its interfaces:
```
vagrant@k8s-master:~$ sudo vppctl
    _______    _        _   _____  ___ 
 __/ __/ _ \  (_)__    | | / / _ \/ _ \
 _/ _// // / / / _ \   | |/ / ___/ ___/
 /_/ /____(_)_/\___/   |___/_/  /_/    

vpp# sh interface
              Name               Idx       State          Counter          Count     
              Name               Idx    State  MTU (L3/IP4/IP6/MPLS)     Counter          Count     
GigabitEthernet0/8/0              1      up          9000/0/0/0     rx packets                     8
                                                                    rx bytes                     821
                                                                    tx packets                     9
                                                                    tx bytes                     566
                                                                    drops                          5
                                                                    ip4                            3
...                                                     
```
Make sure that `GigabitEthernet0/8/0` is listed and that its status is `up`. 

Next, create an example deployment of nginx pods:
```
vagrant@k8s-master:~$ kubectl run nginx --image=nginx --replicas=2
deployment "nginx" created
```
Check the status of the deployment:

```
vagrant@k8s-master:~$ kubectl get deploy -o wide

NAME      DESIRED   CURRENT   UP-TO-DATE   AVAILABLE   AGE       CONTAINERS   IMAGES    SELECTOR
nginx     2         2         2            2           2h        nginx        nginx     run=nginx
```

Verify that the pods in the deployment are up & running:
```
vagrant@k8s-master:~$ kubectl get pods -o wide

NAME                   READY     STATUS    RESTARTS   AGE       IP         NODE
nginx-8586cf59-6kx2m   1/1       Running   1          1h        10.1.2.3   k8s-worker1
nginx-8586cf59-j5vf9   1/1       Running   1          1h        10.1.2.2   k8s-worker1
```

Issue an HTTP GET request to a pod in the deployment:

```
vagrant@k8s-master:~$ wget 10.1.2.2

--2018-01-19 12:34:08--  http://10.1.2.2/
Connecting to 10.1.2.2:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 612 [text/html]
Saving to: ‘index.html.1’

index.html.1                100%[=========================================>]     612  --.-KB/s    in 0s      

2018-01-19 12:34:08 (1.78 MB/s) - ‘index.html.1’ saved [612/612]
```

#### How to SSH into k8s worker node

```
$ cd vagrant
$ vagrant status
$ vagrant ssh k8s-worker1
```
