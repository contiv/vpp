# update the version tag when moving to a new version of the vpp-agent
FROM ligato/vpp-agent:v1.0.5

# set work directory
WORKDIR /root/

# add the agent binary
COPY binaries/contiv-agent /usr/bin/

# add supervisord config file
COPY supervisord.conf /etc/supervisord.conf

# run supervisord as the default executable
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
