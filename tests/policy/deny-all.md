# DENY all traffic to an application

This NetworkPolicy will drop all traffic to pods of an
application and apply to all pods that match the Label Selector criteria.

- Simplest policy that blacklists all the traffic.
- No communication from any other pod is allowed.

### Example
    
Create the following YAML file `test-deny-all.yaml`
and apply using kubectl

```yaml
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: test-deny-all
spec:
  podSelector:
    matchLabels:
      role: db
      ldpreload: true
```

```
$ kubectl apply -f policy-deny-all.yaml
```

## Try it out

### Cleanup

```
kubectl delete networkpolicy test-deny-all
```
