#! /bin/bash

taskset -c 1 wrk -t 1 -c 50 -d 180s http://10.1.1.3:80/index.html
