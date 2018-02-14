## Contiv-VPP Vagrant Installation

### Creating / shutting down / destroying the cluster:
This folder contains the Vagrant file to create a single or multi-node 
Kubernetes cluster using Contiv-VPP as a Network Plugin. 

It is organized into two subfolders:

 - (config) - contains the files needed to share cluster information, used
   during the provisioning stage (master IP address, Certificates, hash-keys).
   Editing is not recommended!
 - (vagrant-scripts) - contains scripts for creating, destroying, rebooting
    and shuting down the VMs that host the K8s cluster.

If you wish to change the default number of nodes, set K8S_NODES before running
vagrant-up.sh:
```
# For a single node setup:
export K8S_NODES=0
# For a two node setup:
export K8S_NODES=1
```

By default, if you do not specify the number of nodes in the environment 
variable, two nodes (one master, one worker) are created.

To create and run the cluster run vagrant-up.sh script, located inside 
vagrant-scripts folder. You can choose to deploy between the testing (use the 
-t flag or leave empty) and the development environment (use the -d flag) when 
running the vagrant-up.sh script. Instructions on how to build the development
contiv/vpp-vswitch image can be found in the next paragraph.

_For the testing environment run:_
```
cd vagrant-scripts/
./vagrant-up.sh
```

_For the development environment run:_
```
cd vagrant-scripts/
./vagrant-up.sh -d
```

To destroy and clean-up the cluster run vagrant-cleanup.sh script, located
inside vagrant-scripts folder:
```
cd vagrant-scripts/
./vagrant-cleanup.sh
```

To shutdown the cluster run vagrant-shutdown.sh script, located inside 
vagrant-scripts folder:
```
cd vagrant-scripts/
./vagrant-shutdown.sh
```

To reboot the cluster run vagrant-reload.sh script, located inside 
vagrant-scripts folder:
```
cd vagrant-scripts/
./vagrant-reload.sh
```

From a suspended state, or after a reboot of the host machine, the cluster
can be brought up by running the vagrant-up.sh script.


### Building and deploying the dev-contiv-vswitch image (optional)
If you chose the deployment with the development environment follow the
instructions to build a modified contivvpp/vswitch image.

1. Make sure changes in the code have been saved. From the k8s-master node, 
   build the new contivvpp/vswitch image (run as sudo)

```
export VAGRANT_VAGRANTFILE=../Vagrantfile-dev; vagrant ssh k8s-master
cd /vagrant/config
sudo ./save-dev-image.sh
```

2. The newly built contivvpp/vswitch image is now tagged as latest. Verify 
with `sudo docker images`; contivvpp/vswitch should have been created a few
seconds ago. The new image with all the changes must become available to all
the nodes in the K8s cluster. To do so, load the docker image into the running
worker nodes (run as sudo).

```
export VAGRANT_VAGRANTFILE=../Vagrantfile-dev; vagrant ssh k8s-worker1 
cd /vagrant/config
sudo ./load-dev-image.sh
```

Verify with `sudo docker images`; old contivvpp/vswitch should now be tagged as
`<none>` and the latest tagged  contivvpp/vswitch should have been created a
few seconds ago.

### Exploring the cluster:
Once the cluster is up, log into the master:
```
cd vagrant-scripts

export VAGRANT_VAGRANTFILE=../Vagrantfile-prod; vagrant ssh k8s-master

Welcome to Ubuntu 16.04 LTS (GNU/Linux 4.4.0-21-generic x86_64)

 * Documentation:  https://help.ubuntu.com/
vagrant@k8s-master:~$ 
```
Verify the Kubernetes/Contiv-VPP installation. First, verify the nodes
in the cluster:

```apple js
vagrant@k8s-master:~$ kubectl get nodes -o wide

NAME          STATUS    ROLES     AGE       VERSION   EXTERNAL-IP   OS-IMAGE           KERNEL-VERSION     CONTAINER-RUNTIME
k8s-master    Ready     master    22m       v1.9.2    <none>        Ubuntu 16.04 LTS   4.4.0-21-generic   docker://17.12.0-ce
k8s-worker1   Ready     <none>    15m       v1.9.2    <none>        Ubuntu 16.04 LTS   4.4.0-21-generic   docker://17.12.0-ce
```

Next, verify that all pods are running correctly:

```
vagrant@k8s-master:~$ kubectl get pods -n kube-system -o wide

NAME                                 READY     STATUS             RESTARTS   AGE       IP             NODE
contiv-etcd-2ngdc                    1/1       Running            0          17m       192.169.1.10   k8s-master
contiv-ksr-x7gsq                     1/1       Running            3          17m       192.169.1.10   k8s-master
contiv-vswitch-9bql6                 2/2       Running            0          17m       192.169.1.10   k8s-master
contiv-vswitch-hpt2x                 2/2       Running            0          10m       192.169.1.11   k8s-worker1
etcd-k8s-master                      1/1       Running            0          16m       192.169.1.10   k8s-master
kube-apiserver-k8s-master            1/1       Running            0          16m       192.169.1.10   k8s-master
kube-controller-manager-k8s-master   1/1       Running            0          15m       192.169.1.10   k8s-master
kube-dns-6f4fd4bdf-62rv4             2/3       CrashLoopBackOff   14         17m       10.1.1.2       k8s-master
kube-proxy-bvr74                     1/1       Running            0          10m       192.169.1.11   k8s-worker1
kube-proxy-v4fzq                     1/1       Running            0          17m       192.169.1.10   k8s-master
kube-scheduler-k8s-master            1/1       Running            0          16m       192.169.1.10   k8s-master
```

If you want your pods to be scheduled on both the master and the workers,
you have to untaint the master node:
```

```

Check VPP and its interfaces:
```apple js
vagrant@k8s-master:~$ telnet 0 5002
Trying 0.0.0.0...
Connected to 0.
Escape character is '^]'.
    _______    _        _   _____  ___ 
 __/ __/ _ \  (_)__    | | / / _ \/ _ \
 _/ _// // / / / _ \   | |/ / ___/ ___/
 /_/ /____(_)_/\___/   |___/_/  /_/    

vpp# sh interface
              Name               Idx       State          Counter          Count     
GigabitEthernet0/8/0              1         up       rx packets                    14
                                                     rx bytes                    3906
                                                     tx packets                    18
                                                     tx bytes                    2128
                                                     drops                          3
                                                     ip4                           13
...
                                                     
```
Make sure that `GigabitEthernet0/8/0` is listed and that its status is `up`. 

Next, create an example deployment of nginx pods:
```
vagrant@k8s-master:~$ kubectl run nginx --image=nginx --replicas=2
deployment "nginx" created
```
Check the status of the deployment:

```apple js
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
cd vagrant-scripts

vagrant status

export VAGRANT_VAGRANTFILE=../Vagrantfile-prod; vagrant ssh k8s-worker1
```
