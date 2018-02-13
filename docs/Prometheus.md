# Prometheus statistics

Each contiv-agent exposes statistics in prometheus format at port `9999` by default. 
Exposed data is split into two groups:
- `/stats`  provides statistics for the interfaces of the vpp managed by contiv-agent
- `/metrics` provides general go runtime statistics

In order to access promethus stats of a node you can use `curl localhost:9999/stats` from the node
The output of contiv-agent running at k8s master node looks similar to

```
$ curl localhost:9999/stats
# HELP dropPackets Number of dropped packets for interface
# TYPE dropPackets gauge
dropPackets{interfaceName="tapb8b972f33301fa5",node="dev",podName="kube-dns-6f4fd4bdf-zgmx9",podNamespace="kube-system"} 16
dropPackets{interfaceName="tapf6870f7f176cf70",node="dev",podName="web-667bdcb4d8-v8mgb",podNamespace="default"} 7
dropPackets{interfaceName="vxlanBVI",node="dev",podName="--",podNamespace="--"} 0
# HELP inBytes Number of received bytes for interface
# TYPE inBytes gauge
inBytes{interfaceName="tapb8b972f33301fa5",node="dev",podName="kube-dns-6f4fd4bdf-zgmx9",podNamespace="kube-system"} 285004
inBytes{interfaceName="tapf6870f7f176cf70",node="dev",podName="web-667bdcb4d8-v8mgb",podNamespace="default"} 586
inBytes{interfaceName="vxlanBVI",node="dev",podName="--",podNamespace="--"} 0
# HELP inErrorPackets Number of received packets with error for interface
# TYPE inErrorPackets gauge
inErrorPackets{interfaceName="tapb8b972f33301fa5",node="dev",podName="kube-dns-6f4fd4bdf-zgmx9",podNamespace="kube-system"} 0
inErrorPackets{interfaceName="tapf6870f7f176cf70",node="dev",podName="web-667bdcb4d8-v8mgb",podNamespace="default"} 0
inErrorPackets{interfaceName="vxlanBVI",node="dev",podName="--",podNamespace="--"} 0
# HELP inMissPackets Number of missed packets for interface
# TYPE inMissPackets gauge
inMissPackets{interfaceName="tapb8b972f33301fa5",node="dev",podName="kube-dns-6f4fd4bdf-zgmx9",podNamespace="kube-system"} 0
inMissPackets{interfaceName="tapf6870f7f176cf70",node="dev",podName="web-667bdcb4d8-v8mgb",podNamespace="default"} 0
inMissPackets{interfaceName="vxlanBVI",node="dev",podName="--",podNamespace="--"} 0
# HELP inNobufPackets Number of received packets ??? for interface
# TYPE inNobufPackets gauge
inNobufPackets{interfaceName="tapb8b972f33301fa5",node="dev",podName="kube-dns-6f4fd4bdf-zgmx9",podNamespace="kube-system"} 0
inNobufPackets{interfaceName="tapf6870f7f176cf70",node="dev",podName="web-667bdcb4d8-v8mgb",podNamespace="default"} 0
inNobufPackets{interfaceName="vxlanBVI",node="dev",podName="--",podNamespace="--"} 0
# HELP inPackets Number of received packets for interface
# TYPE inPackets gauge
inPackets{interfaceName="tapb8b972f33301fa5",node="dev",podName="kube-dns-6f4fd4bdf-zgmx9",podNamespace="kube-system"} 1305
inPackets{interfaceName="tapf6870f7f176cf70",node="dev",podName="web-667bdcb4d8-v8mgb",podNamespace="default"} 7
inPackets{interfaceName="vxlanBVI",node="dev",podName="--",podNamespace="--"} 0
# HELP ipv4Packets Number of ipv4 packets for interface
# TYPE ipv4Packets gauge
ipv4Packets{interfaceName="tapb8b972f33301fa5",node="dev",podName="kube-dns-6f4fd4bdf-zgmx9",podNamespace="kube-system"} 1293
ipv4Packets{interfaceName="tapf6870f7f176cf70",node="dev",podName="web-667bdcb4d8-v8mgb",podNamespace="default"} 0
ipv4Packets{interfaceName="vxlanBVI",node="dev",podName="--",podNamespace="--"} 0
# HELP ipv6Packets Number of ipv6 packets for interface
# TYPE ipv6Packets gauge
ipv6Packets{interfaceName="tapb8b972f33301fa5",node="dev",podName="kube-dns-6f4fd4bdf-zgmx9",podNamespace="kube-system"} 12
ipv6Packets{interfaceName="tapf6870f7f176cf70",node="dev",podName="web-667bdcb4d8-v8mgb",podNamespace="default"} 7
ipv6Packets{interfaceName="vxlanBVI",node="dev",podName="--",podNamespace="--"} 0
# HELP outBytes Number of transmitted bytes for interface
# TYPE outBytes gauge
outBytes{interfaceName="tapb8b972f33301fa5",node="dev",podName="kube-dns-6f4fd4bdf-zgmx9",podNamespace="kube-system"} 290357
outBytes{interfaceName="tapf6870f7f176cf70",node="dev",podName="web-667bdcb4d8-v8mgb",podNamespace="default"} 0
outBytes{interfaceName="vxlanBVI",node="dev",podName="--",podNamespace="--"} 0
# HELP outErrorPackets Number of transmitted packets with error for interface
# TYPE outErrorPackets gauge
outErrorPackets{interfaceName="tapb8b972f33301fa5",node="dev",podName="kube-dns-6f4fd4bdf-zgmx9",podNamespace="kube-system"} 0
outErrorPackets{interfaceName="tapf6870f7f176cf70",node="dev",podName="web-667bdcb4d8-v8mgb",podNamespace="default"} 0
outErrorPackets{interfaceName="vxlanBVI",node="dev",podName="--",podNamespace="--"} 0
# HELP outPackets Number of transmitted packets for interface
# TYPE outPackets gauge
outPackets{interfaceName="tapb8b972f33301fa5",node="dev",podName="kube-dns-6f4fd4bdf-zgmx9",podNamespace="kube-system"} 1332
outPackets{interfaceName="tapf6870f7f176cf70",node="dev",podName="web-667bdcb4d8-v8mgb",podNamespace="default"} 0
outPackets{interfaceName="vxlanBVI",node="dev",podName="--",podNamespace="--"} 0
# HELP puntPackets Number of punt packets for interface
# TYPE puntPackets gauge
puntPackets{interfaceName="tapb8b972f33301fa5",node="dev",podName="kube-dns-6f4fd4bdf-zgmx9",podNamespace="kube-system"} 0
puntPackets{interfaceName="tapf6870f7f176cf70",node="dev",podName="web-667bdcb4d8-v8mgb",podNamespace="default"} 0
puntPackets{interfaceName="vxlanBVI",node="dev",podName="--",podNamespace="--"} 0

```


In order to browse stats in web UI prometheus can be started locally following 
[the guide](https://prometheus.io/docs/prometheus/latest/getting_started/).

If you start prometheus on a node, the following sample config can be used:
```yaml 
global:
  scrape_interval:     15s

scrape_configs:
  - job_name: 'contiv_stats'
    metrics_path: '/stats'
    static_configs:
      - targets: ['localhost:9999']
  - job_name: 'contiv_agent'
    # metrics_path defaults to '/metrics'
    static_configs:
      - targets: ['localhost:9999']
```

Once the prometheus is started with the specified config you should be able access web UI at `localhost:9090`.
```
tester@dev:~/Downloads/prometheus-2.1.0.linux-amd64$ ./prometheus --config.file=config.yml
```
