FROM ligato/vpp-agent

WORKDIR /root/

# copy the binaries
# use ADD instead of COPY, because ADD will uncompress automatically
ADD contiv.tar.gz .

# copy binaries from root home to /usr/bin/
RUN cp /root/contiv/* /usr/bin/

# add supervisor conf file
COPY supervisord.conf /etc/supervisord.conf

# run supervisor as the default executable
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]
