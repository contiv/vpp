FROM alpine:3.6

# set work directory
WORKDIR /root/

# copy the binary
ADD binaries/contiv-ksr .

# run ksr by default
CMD ["/root/contiv-ksr"]