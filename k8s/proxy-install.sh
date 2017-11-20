#!/bin/bash
# Copyright (c) 2017 Cisco and/or its affiliates.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

sudo docker pull contivvpp/kube-proxy:v1.8.0
sudo docker pull contivvpp/kube-proxy:v1.8.1
sudo docker pull contivvpp/kube-proxy:v1.8.2
sudo docker pull contivvpp/kube-proxy:v1.8.3
sudo docker pull contivvpp/kube-proxy:v1.8.4

sudo docker tag contivvpp/kube-proxy:v1.8.0 gcr.io/google_containers/kube-proxy-amd64:v1.8.0
sudo docker tag contivvpp/kube-proxy:v1.8.1 gcr.io/google_containers/kube-proxy-amd64:v1.8.1
sudo docker tag contivvpp/kube-proxy:v1.8.2 gcr.io/google_containers/kube-proxy-amd64:v1.8.2
sudo docker tag contivvpp/kube-proxy:v1.8.3 gcr.io/google_containers/kube-proxy-amd64:v1.8.3
sudo docker tag contivvpp/kube-proxy:v1.8.4 gcr.io/google_containers/kube-proxy-amd64:v1.8.4
