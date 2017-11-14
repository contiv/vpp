### iPerf ldpreload k8s deployment files

This folder contains example YAML files that can be used to deploy ldpreload-ed iperf
on a k8s cluster with Contiv-VPP network plugin.

Note that Contiv-CRI shim needs to be installed and running in order to make this working.

#### 1. Deploy iperf server
```
$ kubectl apply -f iperf-server.yaml
```

#### 2. Verify that the server is running correctly
```
$ kubectl get pods -o wide
NAME                            READY     STATUS    RESTARTS   AGE       IP         NODE
iperf-server-5574dcc986-g8fbv   1/1       Running   0          8s        10.1.1.3   ubuntu
```

Verify the binding on the VPP, on the host where the server POD has been deployed:
```
$ telnet 0 5002
vpp# sh app server
Connection                              App                 
[#0][T] 10.1.1.3:5201->0.0.0.0:0        vcom-app-1          
```

#### 3. Test the connectivity from the host
```
$ iperf3 -V4 -c 10.1.1.3
iperf 3.0.11
Linux ubuntu 4.4.0-98-generic #121-Ubuntu SMP Tue Oct 10 14:24:03 UTC 2017 x86_64 x86_64 x86_64 GNU/Linux
Time: Mon, 13 Nov 2017 12:37:01 GMT
Connecting to host 10.1.1.3, port 5201
      Cookie: ubuntu.1510576621.398595.45f103034db
      TCP MSS: 1428 (default)
[  4] local 172.30.1.2 port 56174 connected to 10.1.1.3 port 5201
Starting Test: protocol: TCP, 1 streams, 131072 byte blocks, omitting 0 seconds, 10 second test
[ ID] Interval           Transfer     Bandwidth       Retr  Cwnd
[  4]   0.00-1.00   sec  44.8 MBytes   375 Mbits/sec  1734   27.9 KBytes       
[  4]   1.00-2.00   sec  41.7 MBytes   350 Mbits/sec  1493   34.9 KBytes       
[  4]   2.00-3.00   sec  23.1 MBytes   194 Mbits/sec  896   18.1 KBytes       
[  4]   3.00-4.00   sec  59.3 MBytes   497 Mbits/sec  1924   18.1 KBytes       
[  4]   4.00-5.00   sec  53.8 MBytes   451 Mbits/sec  1884   26.5 KBytes       
[  4]   5.00-6.00   sec  49.5 MBytes   415 Mbits/sec  1742   26.5 KBytes       
[  4]   6.00-7.00   sec  56.5 MBytes   473 Mbits/sec  1999   37.7 KBytes       
[  4]   7.00-8.00   sec  58.6 MBytes   492 Mbits/sec  2221   13.9 KBytes       
[  4]   8.00-9.00   sec  29.4 MBytes   246 Mbits/sec  1193   30.7 KBytes       
[  4]   9.00-10.00  sec  44.4 MBytes   373 Mbits/sec  1834   20.9 KBytes       
- - - - - - - - - - - - - - - - - - - - - - - - -
Test Complete. Summary Results:
[ ID] Interval           Transfer     Bandwidth       Retr
[  4]   0.00-10.00  sec   461 MBytes   387 Mbits/sec  16920             sender
[  4]   0.00-10.00  sec   461 MBytes   386 Mbits/sec                  receiver
CPU Utilization: local/sender 1.3% (0.2%u/1.1%s), remote/receiver 98.4% (97.6%u/0.8%s)

iperf Done.
```

#### 4. Test the connectivity from the ldpreload-ed iPerf client container
Deploy the client POD:
```
$ kubectl apply -f iperf-client.yaml
```

Verify the deployment:
```
$ kubectl get pods -o wide
NAME                            READY     STATUS    RESTARTS   AGE       IP         NODE
iperf-client-6f776fdc5c-62gj5   1/1       Running   0          5s        10.1.1.4   ubuntu
```

Run bash in the container:
```
$ kubectl exec -it iperf-client-6f776fdc5c-62gj5 bash

[12] vcom_init...done!

[12] vcom_constructor...done!
root@test-client-6ff7bf6d78-tgv9t:/# 
```

Test the connectivity:
```
# iperf3 -V4 -c 10.1.1.3

[24] vcom_init...done!

[24] vcom_constructor...done!
iperf 3.0.7

[26] vcom_init...done!

[26] vcom_constructor...done!

[28] vcom_init...done!

[28] vcom_constructor...done!
Linux test-client-6ff7bf6d78-tgv9t 4.4.0-98-generic #121-Ubuntu SMP Tue Oct 10 14:24:03 UTC 2017 x86_64 GNU/Linux
Time: Mon, 13 Nov 2017 12:55:07 GMT
Connecting to host 10.1.1.3, port 5201
      Cookie: test-client-6ff7bf6d78-tgv9t.1510577
      TCP MSS: 0 (default)
[  8] local :: port 0 connected to :: port 5201
Starting Test: protocol: TCP, 1 streams, 131072 byte blocks, omitting 0 seconds, 10 second test
[ ID] Interval           Transfer     Bandwidth       Retr  Cwnd
[  8]   0.00-1.00   sec  13.5 GBytes   116 Gbits/sec  2448297984   0.00 Bytes       
[  8]   1.00-2.00   sec  14.3 GBytes   123 Gbits/sec    0   0.00 Bytes       
[  8]   2.00-3.00   sec  14.1 GBytes   121 Gbits/sec    0   0.00 Bytes       
[  8]   3.00-4.00   sec  14.9 GBytes   128 Gbits/sec    0   0.00 Bytes       
[  8]   4.00-5.00   sec  14.5 GBytes   125 Gbits/sec    0   0.00 Bytes       
[  8]   5.00-6.00   sec  14.4 GBytes   123 Gbits/sec    0   0.00 Bytes       
[  8]   6.00-7.00   sec  14.3 GBytes   123 Gbits/sec    0   0.00 Bytes       
[  8]   7.00-8.00   sec  13.0 GBytes   112 Gbits/sec    0   0.00 Bytes       
[  8]   8.00-9.00   sec  14.5 GBytes   124 Gbits/sec    0   0.00 Bytes       
[  8]   9.00-10.00  sec  13.1 GBytes   113 Gbits/sec  1846669313   0.00 Bytes       
- - - - - - - - - - - - - - - - - - - - - - - - -
Test Complete. Summary Results:
[ ID] Interval           Transfer     Bandwidth       Retr
[  8]   0.00-10.00  sec   141 GBytes   121 Gbits/sec    1             sender
[  8]   0.00-10.00  sec   141 GBytes   121 Gbits/sec                  receiver
CPU Utilization: local/sender 97.1% (95.3%u/1.8%s), remote/receiver 97.2% (95.8%u/1.4%s)

iperf Done.

[24] vcom_destroy...done!

[24] vcom_destructor...done!
```
