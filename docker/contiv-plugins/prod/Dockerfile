FROM alpine:3.6

WORKDIR /root/

# copy the binaries
# use ADD instead of COPY, because ADD will uncompress automatically
ADD contiv.tar.gz .

# copy binaries from root home to /usr/bin/
RUN cp /root/contiv/* /usr/bin/

# set work directory
WORKDIR /root/

# run shell by default
CMD ["/bin/sh"]