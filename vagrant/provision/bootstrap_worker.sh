#!/usr/bin/env bash
set -ex

echo Args passed: [[ $@ ]]

# Load images if present
if [ -f /vagrant/images.tar ]; then
    echo "Found saved images at /vagrant/images.tar"
    docker load -i /vagrant/images.tar
fi

source /vagrant/config/init

if [ "${dep_scenario}" != 'nostn' ] && [ "${ip_version}" != 'ipv6' ]; then
  export KUBE_WORKER_IP=$(hostname -I | cut -f2 -d' ')
else
  export KUBE_WORKER_IP=$2
fi

sed 's/127\.0\.1\.1.*k8s.*/'"$KUBE_WORKER_IP"' '"$1"'/' -i /etc/hosts
echo "export no_proxy='$1,$KUBE_MASTER_IP,$KUBE_WORKER_IP,localhost,127.0.0.1'" >> /etc/profile.d/envvar.sh
echo "export no_proxy='$1,$KUBE_MASTER_IP,$KUBE_WORKER_IP,localhost,127.0.0.1'" >> /home/vagrant/.profile
source /etc/profile.d/envvar.sh
source /home/vagrant/.profile

if [ "${dep_scenario}" != 'nostn' ]; then
  curl -s https://raw.githubusercontent.com/contiv/vpp/master/k8s/stn-install.sh > /tmp/contiv-stn.sh
  chmod +x /tmp/contiv-stn.sh
  sudo /tmp/contiv-stn.sh
fi

# Based on kubernetes version, disable hugepages in Kubelet
# Join the kubernetes cluster
split_k8s_version="$(cut -d "." -f 2 <<< "${k8s_version}")"
if [ $split_k8s_version -gt 10 ] ; then
  if [ "${node_os_release}" == "16.04" ] ; then
    sed -i '1s/.*/KUBELET_EXTRA_ARGS=--node-ip='"$KUBE_WORKER_IP"' --feature-gates HugePages=false/' /etc/default/kubelet
  else
    sed -i '1s/.*/KUBELET_EXTRA_ARGS=--resolv-conf=\/run\/systemd\/resolve\/resolv.conf --node-ip='"$KUBE_WORKER_IP"' --feature-gates HugePages=false/' /etc/default/kubelet
  fi
  systemctl daemon-reload
  systemctl restart kubelet
else
  sed -i '4 a Environment="KUBELET_EXTRA_ARGS=--node-ip='"$KUBE_WORKER_IP"' --feature-gates HugePages=false"' /etc/systemd/system/kubelet.service.d/10-kubeadm.conf
  systemctl daemon-reload
  systemctl restart kubelet
fi

hash=$(awk 'END {print $NF}' /vagrant/config/cert)

if [ "${ip_version}" != "ipv6" ]; then
  kubeadm join --token "${KUBEADM_TOKEN}"  "${KUBE_MASTER_IP}":6443 --discovery-token-ca-cert-hash "$hash"
else
  kubeadm join --token "${KUBEADM_TOKEN}"  ["${KUBE_MASTER_IP}"]:6443 --discovery-token-ca-cert-hash "$hash"
fi
