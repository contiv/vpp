# Allow limited traffic to a Pod

This Network Policy allows traffic only from specific Pods in a namespace

**Use Case:**
- Allow traffic to a service, only from other services that request access.

## Network Policy > allow-limited-traffic.yaml

Create allow-limited-traffic.yaml using the following manifest:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-limited-traffic
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
            app: frontend 
```

### Example

A pod has labels `role=db` and `app=webstore`. Use the following NetworkPolicy `allow-limited-traffic.yaml` to restrict the access
only to pods with label `app=frontend`:

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

Create Pod2 to test if it can access Pod1, that has the NetworkPolicy attached.
Traffic should be routed into Pod1: 
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

Create Pod3 to test if it can access Pod1, that has the NetworkPolicy attached.
Traffic should NOT be routed into Pod1: 
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
$ kubectl apply -f allow-limited-traffic.yaml
```

Start an application using netcat listening on port 8080 from Pod1 and wait for incoming connections. 
Use ```ifconfig``` to get the IP Address of the Pod
```
$ kubectl exec -it pod1 netcat -- -l -p 8080
```

From another session, try to access Pod1 from Pod2, where 10.1.1.xxx is the IP Address of Pod1: 
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
