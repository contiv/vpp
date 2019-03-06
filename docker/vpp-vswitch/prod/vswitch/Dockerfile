FROM ubuntu:18.04

RUN apt-get update \
 && apt-get install -y \
        # vpp requirements
        openssl libapr1 libnuma1 libmbedcrypto1 libmbedtls10 libmbedx509-0 \
        # required for disabling TCP checksum offload in containers
        ethtool \
        # network tools
        iproute2 iputils-ping inetutils-traceroute \
        # ability to run vpptrace.sh
        netcat-openbsd \
        # ability to visualize graph of configured objects
        graphviz \
 && rm -rf /var/lib/apt/lists/*

# set work directory
WORKDIR /root/

# add the agent binaries
COPY binaries/contiv-init binaries/contiv-agent /usr/bin/

# add VPP binaries (add also extracts from .tar.gz)
ADD binaries/vpp.tar.gz .
RUN dpkg -i vpp/vpp-lib_*.deb vpp/vpp_*.deb vpp/vpp-plugins_*.deb && \
    rm -rf vpp

# add debug scripts
ADD binaries/vpptrace.sh .

# add defualt VPP startup config as contiv-vswitch.conf
COPY vswitch/vpp.conf /etc/vpp/contiv-vswitch.conf
COPY vswitch/govpp.conf /etc/govpp/govpp.conf
COPY vswitch/vppctl /usr/local/bin/vppctl

# run contiv-init as the default executable
CMD ["/usr/bin/contiv-init"]
