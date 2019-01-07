#!/bin/bash

if [ "$#" -ne 1 ]; then
    echo "Please enter Docker container ID (from 'docker ps')"
    exit
fi

pid=`sudo docker inspect --format '{{.State.Pid}}' $1`

echo "Entering namespace of container $1 PID $pid"

sudo nsenter -t "$pid" -n /bin/bash
