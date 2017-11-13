FROM lyft/envoy:latest
RUN apt-get update
COPY envoy.json /etc/envoy.json
CMD /usr/local/bin/envoy -c /etc/envoy.json

