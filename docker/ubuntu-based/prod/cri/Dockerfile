FROM ubuntu:16.04

# install iproute2 - required by dockershim
RUN apt-get update && apt-get install -y iproute2 &&\
    rm -rf /var/lib/apt/lists/*

# set work directory
WORKDIR /root/

# copy the binary
ADD binaries/contiv-cri .

# run cri by default
CMD ["/root/contiv-cri"]
