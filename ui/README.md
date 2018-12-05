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

### Running

From this directory run one of these commands:
- `./start.sh` for fully automated setup - run 2 workers in production enviroment without STN along with kubectl proxy
- `./start-professional.sh` for manual settings

When everything is installed, navigate to `http://localhost:4300/` on Chrome with disabled web security.

### Accessing APIs

#### Set kubectl proxy
In case you chose "manual settings", the kubectl proxy must be set in order to access APIs. Run `vagrant ssh k8s-master` from backend vagrant's folder for connecting to the-k8s master node. When connected, run `kubectl proxy --port=8080 &` in order to access APIs on k8s master's localhost. You can test the APIs by running `curl http://localhost:8080/api/` from k8s-master node - [more info](https://kubernetes.io/docs/tasks/access-application-cluster/access-cluster/).

### Postman collection
[Collection](./data/ContivVPP.postman_collection.json)
