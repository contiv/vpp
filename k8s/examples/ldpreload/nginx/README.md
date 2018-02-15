### NGINX ldpreload k8s deployment files

This folder contains example YAML files that can be used to deploy ldpreload-ed nginx
on a k8s cluster with Contiv-VPP network plugin.

Note that Contiv-CRI shim needs to be installed and running in order to make this working.

#### 1. Deploy iperf server
```
$ kubectl apply -f nginx-server.yaml
```

#### 2. Verify that the server is running correctly
```
$ kubectl get pods -o wide
NAME                           READY     STATUS    RESTARTS   AGE       IP         NODE
nginx-server-7686d857c-x922b   1/1       Running   0          5s        10.1.1.3   vm7
```

Verify the binding on the VPP, on the host where the server POD has been deployed:
```
$ telnet 0 5002
vpp# sh app server
Connection                              App                 
[#0][T] 10.1.1.3:80->0.0.0.0:0          vcom-app-1           
```

#### 3. Test the connectivity from the host
```
$ wget 10.1.1.3
  --2017-11-14 14:23:22--  http://10.1.1.3/
  Connecting to 10.1.1.3:80... connected.
  HTTP request sent, awaiting response... 200 OK
  Length: 612 [text/html]
  Saving to: 'index.html'
  
  index.html                                     100%[=================================================================================================>]     612  --.-KB/s    in 0s      
  
  2017-11-14 14:23:22 (70.4 MB/s) - 'index.html' saved [612/612]
```

#### 4. Test the connectivity from the ldpreload-ed container with wget
Deploy the client POD:
```
$ kubectl apply -f wget-client.yaml
```

Verify the deployment:
```
$ kubectl get pods -o wide
NAME                           READY     STATUS    RESTARTS   AGE       IP         NODE
nginx-server-7686d857c-x922b   1/1       Running   0          2m        10.1.1.3   vm7
wget-client-845877549-lql7z    1/1       Running   0          3s        10.1.1.4   vm7
```

Test the connectivity by running wget in the container:
```
$ kubectl exec -it wget-client-845877549-lql7z wget 10.1.1.3


[30] vcom_init...done!

[30] vcom_constructor...done!
--2017-11-14 14:25:49--  http://10.1.1.3/
Connecting to 10.1.1.3:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 612 [text/html]
Saving to: 'index.html'

index.html          100%[===================>]     612  --.-KB/s    in 0s      

2017-11-14 14:25:49 (86.4 MB/s) - 'index.html' saved [612/612]


[30] vcom_destroy...done!

[30] vcom_destructor...done!
```
