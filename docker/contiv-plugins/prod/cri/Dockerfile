FROM alpine:3.6

# set work directory
WORKDIR /root/

# copy the binary
ADD binaries/contiv-cri .

# run cri by default
CMD ["/root/contiv-cri"]