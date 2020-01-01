## Running robot tests

### Requirements
- python packages installed 
```
$ pip install -r vpp/tests/robot/requirements.txt
```
- k8s cluster installed with vagrant scripts located in vpp/vagrant

#### Details you shoud know about environment setup vs. robot tests 

Setup k8s cluster by cloning the contiv/vpp project and running vagrant scripts localted in vpp/vagrant
```
$ cd vpp/vagrant
$ export K8S_NODE_OS_RELEASE=18.04
$ export K8S_DEPLOYMENT_SCENARIO="nostn"
$ export K8S_NODES=1
$ export IP_VERSION="ipv4"
$ ./vagrant-up
```
Deployment like this creates ".vagrant" directory to be located as vpp/vagrant/.vagrant. It is important, because robot libraries rely on direcotry ".vagrant" to be located in relative path from their possition
```
 ${ro}=    Run Process    vagrant ${subcommand}    shell=True    cwd=${CURDIR}/../../../vagrant
```
When working direcotry is "vagrant", then vagrant ssh command works as expected.
Now you can robot from anywhere
robot -v needed_variables:values any/path/to/tests/robot/suite.robot

### Running robot tests suites

The default k8s cluster dedicated for tests is planned to have 1 master and 2 worker nodes. All pods/deployments are planned to be located on worker nodes. For the development purposes, if not enough RAM is available and only 1 worker is availble, you shoud override test node variables.

Default variables use names given by vagrant scripts. 
```
$ cat variables/Defaults.robot
*** Variables ***
${K8S_MASTER}    k8s-master
${K8S_TEST_NODE1}    k8s-worker1
${K8S_TEST_NODE2}    k8s-worker2
```

Running robot after overriding variales will look like
```
$ robot -v K8S_TEST_NODE1:k8s-master -v K8S_TEST_NODE2:k8s-worker1 sanity.robot
```
