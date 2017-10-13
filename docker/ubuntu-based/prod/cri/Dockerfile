FROM ubuntu:16.04

# set work directory
WORKDIR /root/

# copy the binary
ADD binaries/contiv-cri .

# run cri by default
CMD ["/root/contiv-cri"]