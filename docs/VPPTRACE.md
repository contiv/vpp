## Using vpptrace.sh for VPP packet tracing

VPP allows to trace incoming packets using CLI commands `trace add` and `show trace`
as explained [here](VPP_PACKET_TRACING_K8S.md), but it is a rather cumbersome process.

The buffer for captured packets is limited in size and once it gets full the tracing
stops. The user has to manually clear the buffer content and repeat the trace command
to resume the packet capture, loosing information about all packets received in the meantime.

Packet filtering exposed via the CLI command `trace filter` is also quite limited
in what it can do. Currently there is just one available filter which allows to keep
only packets that include a certain node in the trace or exclude a certain node in the trace.
It is not possible to filter the traffic by its content, e.g. by the source/destination
IP address, protocol, etc.

Last but not least, it is not possible to trace packets on a selected interface
like `tcpdump` allows to do via the option `-i`. VPP is only able to capture packets
on the *RX side* of a selected *device* (e.g. dpdk, virtio, af-packet). Which means
that interfaces based on the same device cannot by traced for incoming packets
individually, but only all at the same time. In Contiv/VPP all pods are connected
with VPP via the same kind of the TAP interface, meaning that it is not possible to
capture packets incoming only from one selected pod.

Contiv/VPP ships with a simple bash script [vpptrace.sh](../scripts/vpptrace.sh)
which helps to alleviate the aforementioned VPP limitations. The script automatically
re-initializes buffer and trace whenever it is close to getting full in order to
avoid packet loss as much as it is possible. Next it allows to filter packets
by the content of the trace. There are two modes of filtering
 - *substring mode* (default): packet trace must contain a given sub-string in order to
    be included in the output
 - *regex mode*: packet trace must match a given regex in order to be printed

The script is still limited in that capture runs only on the RX side of all interfaces
built on the top of a selected device. Using filtering, however, it is possible to limit
traffic by interface simply by using the interface name as a substring to match against.

#### Usage

Run the script without any arguments to get the usage printed:
```
Usage: vpptrace.sh  -i <VPP-IF-TYPE> [-a <VPP-ADDRESS>] [-r] [-f <REGEXP> / <SUBSTRING>]
   -i <VPP-IF-TYPE> : VPP interface *type* to run the packet capture on (e.g. dpdk-input, virtio-input, etc.)
                       - available aliases:
                         - af-packet-input: afpacket, af-packet, veth
                         - virtio-input: tap (version determined from the VPP config), tap2, tapv2
                         - tapcli-rx: tap (version determined from the VPP config), tap1, tapv1
                         - dpdk-input: dpdk, gbe, phys*
   -a <VPP-ADDRESS> : IP address or hostname of the VPP to capture packets from
                      - not supported if VPP listens on a UNIX domain socket
                      - default = 127.0.0.1
   -r               : apply filter string (passed with -f) as a regexp expression
                      - by default the filter is NOT treated as regexp
   -f               : filter string that packet must contain (without -r) or match as regexp (with -r) to be printed
                      - default is no filtering
```

The mandatory option is `VPP-IF-TYPE`, which is the device (e.g. virtio, dpdk, etc.)
to capture the incoming traffic from. Script provides multiple aliases which
are much easier to remember than the device names. For `dpdk-input` one can enter
just `dpdk`, or anything starting with `phys`, etc. For TAPs, the script is even
smart enough to find out the TAP version used, which allows to enter just `tap`
as the device name.

As a general rule, select `dpdk` only for traffic *entering the node from outside*
(not including host stack), otherwise select `tap` or `afpacket`, based on the chosen
interface type for pod-VPP and host-VPP interconnection.

vpptrace.sh can capture packets even from VPP on a different host, provided that
VPP-CLI listens on a port and not on a UNIX domain socket (for security reasons IPC
is the default communication link, see /etc/vpp/contiv-vswitch.conf). Enter the destination
node IP address via the option `-a`(localhost is the default).

The capture can be filtered via the `-f` option. The output will include only packets
whose trace matches/contains the given expression/sub-string.

Option `-r` enables the regex mode for filtering.

#### Examples

1. Capture all packets entering VPP via `tapcli-1` interface **AND** all packets
   leaving VPP via `tapcli-1` that were sent from a pod or the host on the *same node*
   (sent from tap, not Gbe):
```
$ vpptrace.sh -i tap -f "tapcli-1"
```

2. Capture all packets with source or destination IP address 10.1.1.3 sent from a pod
   or the host stack on the same node:
```
$ vpptrace.sh -i tap -f "10.1.1.3"
```

3. Capture all SYN-ACKs received from outside:
```
$ vpptrace.sh -i dpdk -f "SYN-ACK"
```