FROM ubuntu:16.04

RUN apt-get update \
 && apt-get install -y \
        # general tools
        iproute2 iputils-ping inetutils-traceroute \
        # vpp requirements
        openssl python libapr1 libnuma1 libmbedcrypto0 libmbedtls10 libmbedx509-0 \
        supervisor \
        # required for disabling TCP checksum offload in containers
        ethtool \
        # ability to run vpptrace.sh
        netcat-openbsd \
 && rm -rf /var/lib/apt/lists/*

# install ETCD
ENV ETCD_VER=v3.3.9
ENV GOOGLE_URL=https://storage.googleapis.com/etcd
ENV GITHUB_URL=https://github.com/coreos/etcd/releases/download
ENV DOWNLOAD_URL=${GOOGLE_URL}

RUN curl -L ${DOWNLOAD_URL}/${ETCD_VER}/etcd-${ETCD_VER}-linux-amd64.tar.gz -o /tmp/etcd-${ETCD_VER}-linux-amd64.tar.gz
RUN tar xzvf /tmp/etcd-${ETCD_VER}-linux-amd64.tar.gz -C /tmp/etcd --strip-components=1
RUN rm -f /tmp/etcd-${ETCD_VER}-linux-amd64.tar.gz

# use /opt/vpp-agent/dev as the working directory
RUN mkdir /etc/supervisord

# set work directory
WORKDIR /root/

# add the agent binaries
COPY binaries/contiv-init binaries/contiv-agent /usr/bin/

# add VPP binaries (add also extracts from .tar.gz)
ADD binaries/vpp.tar.gz .
RUN dpkg -i vpp/vpp-lib_*.deb vpp/vpp_*.deb vpp/vpp-plugins_*.deb && \
    rm -rf vpp

# add defualt VPP startup config as contiv-vswitch.conf
COPY vswitch/vpp.conf /etc/vpp/contiv-vswitch.conf
COPY vswitch/govpp.conf /etc/govpp/govpp.conf
COPY vswitch/supervisord.conf /etc/supervisord.conf
COPY vswitch/vppctl /usr/local/bin/vppctl

# run supervisord as the default executable
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
