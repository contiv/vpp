# update the version tag when moving to a new version of the vpp-agent
FROM ligato/vpp-agent:pantheon-dev

# set work directory
WORKDIR /root/

# add the agent binary
COPY binaries/contiv-agent /usr/bin/

# add VPP binaries (add also extracts from .tar.gz)
ADD binaries/vpp.tar.gz .
RUN dpkg -i vpp/vpp-lib_*.deb vpp/vpp_*.deb vpp/vpp-plugins_*.deb && \
    rm -rf vpp

# add ldpreload lib
ENV LD_PRELOAD_INSTALL_DIR /opt/ldpreload
ADD binaries/ldpreload.tar.gz /

# rename defualt VPP startup config to contiv-vswitch.conf
RUN mv /etc/vpp/vpp.conf /etc/vpp/contiv-vswitch.conf

# add supervisord config file
COPY vswitch/supervisord.conf /etc/supervisord.conf

# run supervisord as the default executable
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
