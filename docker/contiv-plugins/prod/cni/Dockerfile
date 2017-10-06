FROM alpine:3.6

# set work directory
WORKDIR /root/

# copy the binaries
ADD binaries/contiv-cni .
ADD binaries/loopback .

# add default CNI config
ADD cni/10-contiv-vpp.conf .

# add CNI installation script
ADD cni/install.sh .

# run install script by default
CMD ["/root/install.sh"]