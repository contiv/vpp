### Ldpreload label injecter

Ldpreload label injecter injects ldpreload related labels to kubernetes yaml files.
Examples of injector usage:

For taking content of nginx.yaml file, injecting it with basic ldpreload labels(enabling, app scoping,...) and writing it to standard output:
```
ldpreload-label-injector -f /<somepath>/nginx.yaml
```
For taking content of nginx-source.yaml file, injecting it with basic ldpreload labels(enabling, app scoping,...) and writing it to nginx.yaml file:
```
ldpreload-label-injector -f /<somepath>/nginx-source.yaml -o /<somepath>/nginx.yaml
```
For taking yaml content from standard input, injecting it with basic ldpreload labels(enabling, app scoping,...) and writing it to standard output:
```
ldpreload-label-injector -f -
```
For taking yaml content from standard input, injecting it with basic ldpreload labels and debug ldpreload label and writing it to standard output:
```
ldpreload-label-injector -d -f -
```
For taking yam content(with proxy configuration inside) from standard input, injecting it with basic ldpreload labels and writing it to standard output:
```
ldpreload-label-injector -p proxyContainerName -f -
```
For showing tool help:
```
ldpreload-label-injector -h
```