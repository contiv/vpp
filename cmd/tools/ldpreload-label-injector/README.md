### Ldpreload label injecter

Ldpreload label injecter injects ldpreload related labels to kubernetes yaml files.
Examples of injector usage:

For injecting basic ldpreload labels(enabling, app scoping,...) into nginx.yaml file:
```
ldpreload-label-injector /<somepath>/nginx.yaml
```
For content of nginx-source.yaml file, injecting basic ldpreload labels into it and saving it to nginx.yaml file:
```
ldpreload-label-injector -o /<somepath>/nginx.yaml /<somepath>/nginx-source.yaml
```
For injecting basic ldpreload labels and debug ldpreload label into nginx.yaml file:
```
ldpreload-label-injector -d /<somepath>/nginx.yaml
```
For injecting basic ldpreload labels into yaml file with proxy configured inside:
```
ldpreload-label-injector -p proxyContainerName /<somepath>/nginx.yaml
```
For showing tool help:
```
ldpreload-label-injector
```
or
```
ldpreload-label-injector -h
```