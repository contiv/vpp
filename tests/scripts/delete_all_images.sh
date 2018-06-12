#!/bin/bash
# Delete all images
if [[ $(sudo docker images -q | wc -l) -gt 0 ]]
then
  sudo docker rmi -f $(sudo docker images -q)
else
  echo "No images in docker..."
fi
