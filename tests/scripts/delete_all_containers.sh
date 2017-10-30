#!/bin/bash
# Delete all containers
if [[ $(sudo docker ps -a -q | wc -l) -gt 0 ]]
then
  sudo docker rm -f $(sudo docker ps -a -q)
else
  echo "No containers are running..."
fi
