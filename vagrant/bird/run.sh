#!/bin/bash

docker run -dit --restart always --name bird --net=host --privileged -v /etc/bird:/etc/bird:rw pierky/bird
