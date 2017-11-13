To create the envoy-nginx pod, first create the standalone- envoy docker image
on all worker nodes:

```
sudo docker build -t envoy-pod:v1 .
```

Then, from kube master, create the the envoy-nginx pod:
```
kubectl create -f envoy-pod.yaml
```

Check the deployment:
```
kubectl get pods -o wide
NAME                      READY     STATUS    RESTARTS   AGE       IP          NODE
envoy-nginx               2/2       Running   0          23h       10.1.2.25   cvpp-slave2
  ...
```

To test that it work properly, deploy a busybox pod:
```
kubectl run busybox --rm -it --image=busybox /bin/sh
If you don't see a command prompt, try pressing enter.

/ # wget -S 10.1.2.25
Connecting to 10.1.2.25 (10.1.2.25:80)
  HTTP/1.1 200 OK
  Server: nginx/1.13.6
  Date: Mon, 13 Nov 2017 04:28:58 GMT
  Content-Type: text/html
  Content-Length: 612
  Last-Modified: Thu, 14 Sep 2017 16:35:09 GMT
  Connection: close
  ETag: "59baafbd-264"
  Accept-Ranges: bytes
  
index.html           100% |*******************************************************************************************************************************************************************************************************************************|   612   0:00:00 ETA
/ # 
/ # 
/ # rm index.html 
/ # wget -S 10.1.2.25:10000
Connecting to 10.1.2.25:10000 (10.1.2.25:10000)
  HTTP/1.1 200 OK
  server: envoy
  date: Mon, 13 Nov 2017 04:29:53 GMT
  content-type: text/html
  content-length: 612
  last-modified: Thu, 14 Sep 2017 16:35:09 GMT
  etag: "59baafbd-264"
  accept-ranges: bytes
  x-envoy-upstream-service-time: 0
  connection: close
  
index.html           100% |*******************************************************************************************************************************************************************************************************************************|   612   0:00:00 ETA
/ # 

```