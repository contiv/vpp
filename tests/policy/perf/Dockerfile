FROM ubuntu:16.04
MAINTAINER Cisco Systems

ENV http_proxy http://proxy-wsa.esl.cisco.com:80
ENV https_proxy http://proxy-wsa.esl.cisco.com:80

COPY CPS.sh /
COPY RPS.sh /

RUN chmod u+x /CPS.sh
RUN chmod u+x /RPS.sh

RUN apt-get update; apt-get install build-essential libssl-dev git vim -y
RUN git clone https://github.com/wg/wrk.git wrk
RUN cd wrk; make
RUN cd wrk; cp wrk /usr/local/bin
