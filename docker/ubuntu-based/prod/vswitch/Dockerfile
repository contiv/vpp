# update the version tag when moving to a new version of the vpp-agent
FROM ligato/vpp-agent:pantheon-dev

# install ethtool - required for disabling TCP checksum offload in containers
RUN apt-get update && apt-get install -y ethtool &&\
    rm -rf /var/lib/apt/lists/*

# set work directory
WORKDIR /root/

# add the agent binary
COPY binaries/contiv-agent /usr/bin/

#uninstall any VPP first before re-installing
RUN /bin/bash -c "yes | apt remove vpp* || true"

# add VPP binaries (add also extracts from .tar.gz)
ADD binaries/vpp.tar.gz .
RUN dpkg -i vpp/vpp-lib_*.deb vpp/vpp_*.deb vpp/vpp-plugins_*.deb && \
    rm -rf vpp

# add ldpreload lib
ENV LD_PRELOAD_LIB_DIR /opt/ldpreload/
ADD binaries/ldpreload.tar.gz $LD_PRELOAD_LIB_DIR

# rename defualt VPP startup config to contiv-vswitch.conf
RUN mv /etc/vpp/vpp.conf /etc/vpp/contiv-vswitch.conf

# add supervisord config file
COPY vswitch/supervisord.conf /etc/supervisord.conf

# add govpp config file
COPY vswitch/govpp.conf /etc/govpp/govpp.conf

# run supervisord as the default executable
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
