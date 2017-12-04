# Allow traffic only to a port number of an application.

This NetworkPolicy defines ingress rules for specific ports. 
When no ports are defined, the rule applies to all port numbers.


**NOTE:**
> When ports are exposed to the host, NetworkPolicies will not be aware of the mapped ports. 
> The Network Policy spec, should have the port numbers of the application. 

## Network Policy > allow-port.yaml

Create allow-port.yaml using the following manifest:
  
```yaml
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: allow-port
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: webstore
      role: db
  ingress:
  - ports:
    - port: 8080
    from:
    - podSelector:
        matchLabels:
          role: frontend
```

This network policy will:

- Drop all non-whitelisted traffic to pods with labels "app: webstore" and "role: db".
- Allow traffic on port `8080` from pods with label
  `role=frontend` in the same namespace.

### Example

Use the Network Policy `allow-port.yaml` to allow access to specific port from selected Pods. 

Create Pod1 that policy can be applied: 
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod1
  labels:
    app: webstore
    role: db
spec:
  containers:
  - image: ciscolabs/epapp
    command:
      - sleep
      - "3600"
    imagePullPolicy: IfNotPresent
    name: pod1
  restartPolicy: Always
```

Create Pod2 to test if it can access Pod1 on port 8000: 
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod2
  labels:
    role: frontend
spec:
  containers:
  - image: ciscolabs/epapp
    command:
      - sleep
      - "3600"
    imagePullPolicy: IfNotPresent
    name: pod2
  restartPolicy: Always
```

Create Pod3 to test if it can access port 8000 on Pod1. Access should be denied 
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod3
  labels:
    role: backend
spec:
  containers:
  - image: ciscolabs/epapp
    command:
      - sleep
      - "3600"
    imagePullPolicy: IfNotPresent
    name: pod3
  restartPolicy: Always
```

### Test the policy

Create the Pods: 
```
$ kubectl apply -f pod1.yaml
$ kubectl apply -f pod2.yaml
$ kubectl apply -f pod3.yaml
```

To test the policy after creating all the pods, apply Network Policy. 
```
$ kubectl apply -f allow-port.yaml
```

Now try to access port 8000 from Pod2 to Pod2: 

Start an application using netcat listening on port 8000 from Pod1 and wait for incoming connections. 
Use ```ifconfig``` first to get the IP Address of Pod1. 
```
$ kubectl exec -it pod1 ifconfig
$ kubectl exec -it pod1 netcat -- -l -p 8080
```

From another session, try to access port 8000 of Pod1 from Pod2, where 10.1.1.xxx is the IP Address of Pod1: 
```
$ kubectl exec -it pod2 netcat -- -zvw 1 10.1.1.xxx 8078-8082
```

Do the same for pod3 and verify that access is restricted: 
```
$ kubectl exec -it pod3 netcat -- -zvw 1 10.1.1.xxx 8078-8082
```

### Cleanup
```
$ kubectl delete networkpolicy allow-limited-traffic
$ kubectl delete po pod1 
$ kubectl delete po pod2
$ kubectl delete po pod3
```
