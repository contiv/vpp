# Allow traffic from applications using multiple selectors

This NetworkPolicy lets you define multiple pod selectors to allow traffic from.

**Use Case**
- When more than one applications need to have access to the protected by Policy application.
  

## Network Policy > allow-multiple-selectors.yaml

Create allow-port.yaml using the following manifest:
  
```yaml
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: allow-multiple-selectors
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: webstore
      role: db
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: webstore
          role: frontend
    - podSelector:
        matchLabels:
          app: webstore
          role: backend
    - podSelector:
        matchLabels:
          app: webstore
          role: api
```

- Pods selected are combined and whitelisted (OR'ed).

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

Create Pod2 to test access Pod1: 
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod2
  labels:
    app: webstore
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

Create Pod3 to test access to Pod1: 
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod3
  labels:
    app: webstore
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

Create Pod4 to test access to Pod1: 
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: pod4
  labels:
    app: webstore
    role: api
spec:
  containers:
  - image: ciscolabs/epapp
    command:
      - sleep
      - "3600"
    imagePullPolicy: IfNotPresent
    name: pod4
  restartPolicy: Always
```

### Test the policy

Create the Pods: 
```
$ kubectl apply -f pod1.yaml
$ kubectl apply -f pod2.yaml
$ kubectl apply -f pod3.yaml
$ kubectl apply -f pod4.yaml
```

To test the policy after creating all the pods, apply Network Policy. 
```
$ kubectl apply -f allow-multiple-selectors.yaml
```

Now try to access port any port from Pod2, Pod3, Pod4 to Pod1: 

Start an application using netcat listening on port 8080 from Pod1 and wait for incoming connections. 
Use ```ifconfig``` first to get the IP Address of Pod1. 
```
$ kubectl exec -it pod1 ifconfig
$ kubectl exec -it pod1 netcat -- -l -p 8080
```

From another session, try to access port 8080 of Pod1 from Pod2, where 10.1.1.xxx is the IP Address of Pod1: 
```
$ kubectl exec -it pod2 netcat -- -zvw 1 10.1.1.xxx 8078-8082
$ kubectl exec -it pod3 netcat -- -zvw 1 10.1.1.xxx 8078-8082
$ kubectl exec -it pod4 netcat -- -zvw 1 10.1.1.xxx 8078-8082
```

A Pod without labels can be tested similarly to prove that access is denied. 


### Cleanup
```
$ kubectl delete networkpolicy allow-limited-traffic
$ kubectl delete po pod1 
$ kubectl delete po pod2
$ kubectl delete po pod3
```