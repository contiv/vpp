# Deny all traffic to an application

This Network Policy will drop all traffic to selcted pods using Pod Selectors.

**Use Cases:**
- Run a Pod and prevent any other Pods communicating with it.
- Temporary traffic isolation for a Pod

## Network Policy > deny-all-traffic.yaml

Create deny-all-traffic.yaml using the following manifest:

```yaml
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: deny-all-traffic
  namespace: default
spec:
  podSelector:
    matchLabels:
      app: webstore
      role: db
```

### Example

Use the Network Policy `deny-all-traffic.yaml` to deny access to all selected Pods. 

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

Create Pod2 to test if it can access Pod1, that has the NetworkPolicy attached: 
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


### Test the policy

Create the Pods: 
```
$ kubectl apply -f pod1.yaml
$ kubectl apply -f pod2.yaml
```

To test the policy after creating all the pods, apply Network Policy. 
```
$ kubectl apply -f allow-limited-traffic.yaml
```

Now try to ping from one Pod to the other
Use ```ifconfig``` to get the IP Address of the Pod you need to ping

```
$ kubectl exec -it pod1 ifconfig
$ kubectl exec -it pod2 ping -- -c4 10.1.1.xxx
```

### Cleanup
```
kubectl delete networkpolicy deny-all-traffic
kubectl delete po pod1
kubectl delete po pod2
```

**Note**

If there is at least one NetworkPolicy with a rule allowing the traffic,
it means the traffic will be routed to the Pod even if we have a deny-all policy. 



