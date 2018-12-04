# Contiv VPP UI

This project was generated with [Angular CLI](https://github.com/angular/angular-cli) version 7.0.2.

## Start App

### Prerequisities

- Google Chrome - running with [disabled web security](https://stackoverflow.com/questions/3102819/disable-same-origin-policy-in-chrome) (Important for accessing the APIs).
    ##### -Command in OSX:
    Open -n -a Google\ Chrome --args --disable-web-security --user-data-dir=/tmp/chrome
    ##### -Command in Windows:
    In the "Run" app, enter: chrome.exe --user-data-dir="C://Chrome dev session" --disable-web-security

- Vagrant
- VirtualBox

## Installation

### Backend installation (Contiv VPP)
Clone [Backend](https://github.com/contiv/vpp.git) and follow installation instructions for running [Vagrant version](https://github.com/contiv/vpp/tree/master/vagrant).

### Accessing APIs

#### Set kubectl proxy
When everything is installed, run `vagrant ssh k8s-master` from backend vagrant's folder for connecting to the-k8s master node. When connected, run `kubectl proxy --port=8080 &` in order to access APIs on k8s master's localhost. You can test the APIs by running `curl http://localhost:8080/api/` from k8s-master node - [more info](https://kubernetes.io/docs/tasks/access-application-cluster/access-cluster/).

### Frontend installation
Clone this repository, cd into directory and run `./start.sh`.

When everything is installed, navigate to `http://localhost:4200/` on Chrome with disabled web security.

#### Postman collection
[Collection](./data/ContivVPP.postman_collection.json)
