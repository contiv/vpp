#!/usr/bin/env bash
set -ex

echo Args passed: [[ $@ ]]

# variable should be set to true unless the script is executed for the first master
node_name="$1"
backup_master="$3"

# Pull images if not present
if [ -f /vagrant/images.tar ]; then
    echo 'Found saved images at /vagrant/images.tar'
    docker load -i /vagrant/images.tar
elif [ "${dep_scenario}" != "calico" ]; then
  echo "Pulling Contiv-VPP plugin images..."
  sudo -E ${contiv_dir}/k8s/pull-images.sh -b "${image_tag}"
fi

# --------------------------------------------------------
# ---> Build Contiv/VPP-vswitch Development Image <---
# --------------------------------------------------------

if [ "${dep_env}" = "dev" ]; then
    # wait for apt auto-update to finish so we don't get conflicts
    while `ps aux | grep -q [a]pt`; do
      sleep 20
    done

    sudo -E apt-get install -y xorg \
                            openbox

    echo "Downloading and installing Goland..."
    curl -sL https://download.jetbrains.com/go/goland-"${goland_version}".tar.gz > /tmp/goland.tar.gz
    tar -xvzf /tmp/goland.tar.gz --directory /home/vagrant >/dev/null 2>&1

    if [ -f /vagrant/dev-contiv-vswitch.tar ]; then
        echo "Found saved dev image at /vagrant/dev-contiv-vswitch.tar"
        docker load -i /vagrant/dev-contiv-vswitch.tar
    else
        echo "vagrant" >> ${contiv_dir}/.dockerignore
        echo "Building development contivpp/vswitch image..."
        cd ${contiv_dir}/docker; ./build-all.sh
    fi
fi

# --------------------------------------------------------
# ---> Create token and export it with kube master IP <---
# --------------------------------------------------------

if [ "$backup_master" != "true" ]; then
  echo "Exporting Kube Master IP and Kubeadm Token..."
  echo "export KUBEADM_TOKEN=$(kubeadm token generate)" >> /vagrant/config/init
fi

if [ "${dep_scenario}" != 'nostn' ] && [ "${ip_version}" != 'ipv6' ]; then
  echo "export KUBE_MASTER_IP=$(hostname -I | cut -f2 -d' ')" >> /vagrant/config/init
  source /vagrant/config/init
  sed 's/127\.0\.1\.1.*k8s.*/'"$KUBE_MASTER_IP"' '"$1"'/' -i /etc/hosts
  echo "export no_proxy='$1,$KUBE_MASTER_IP,localhost,127.0.0.1'" >> /etc/profile.d/envvar.sh
  echo "export no_proxy='$1,$KUBE_MASTER_IP,localhost,127.0.0.1'" >> /home/vagrant/.profile
else
  echo "export KUBE_MASTER_IP=$2" >> /vagrant/config/init
  source /vagrant/config/init
  sed 's/127\.0\.1\.1.*k8s.*/'"$2"' '"$1"'/' -i /etc/hosts
  echo "export no_proxy='$1,$KUBE_MASTER_IP,localhost,127.0.0.1'" >> /etc/profile.d/envvar.sh
  echo "export no_proxy='$1,$KUBE_MASTER_IP,localhost,127.0.0.1'" >> /home/vagrant/.profile
fi

source /etc/profile.d/envvar.sh
source /home/vagrant/.profile

# --------------------------------------------------------
# --------------> Kubeadm & Networking <------------------
# --------------------------------------------------------

# Initialize Kubernetes master

service_cidr="10.96.0.0/12"
pod_network_cidr="10.10.0.0/16"
if [ "${ip_version}" == "ipv6" ]; then
  pod_network_cidr="2001::/16"
  service_cidr="2096::/110"
elif [ "${dep_scenario}" != 'calico' ] && [ "${dep_scenario}" != 'calicovpp' ]; then
  pod_network_cidr="10.0.0.0/8"
fi

split_k8s_version="$(cut -d "." -f 2 <<< "${k8s_version}")"

if [ "${node_os_release}" == "16.04" ] ; then
  echo "KUBELET_EXTRA_ARGS=--node-ip=$KUBE_MASTER_IP" > /etc/default/kubelet
else
  echo "KUBELET_EXTRA_ARGS=--node-ip=$KUBE_MASTER_IP --resolv-conf=/run/systemd/resolve/resolv.conf" > /etc/default/kubelet
fi
systemctl daemon-reload
systemctl restart kubelet
if [ "${dep_scenario}" != 'calico' ] && [ "${dep_scenario}" != 'calicovpp' ]; then
  if [ ${master_nodes} -gt 1 ]; then
    cat  > kubeadm.cfg <<EOF
---
apiVersion: kubeadm.k8s.io/v1beta1
bootstrapTokens:
- groups:
  - system:bootstrappers:kubeadm:default-node-token
  token: $KUBEADM_TOKEN
  usages:
  - signing
  - authentication
kind: InitConfiguration
localAPIEndpoint:
  advertiseAddress: $KUBE_MASTER_IP
  bindPort: 6443
nodeRegistration:
  criSocket: /var/run/dockershim.sock
  name: k8s-master
  taints:
  - effect: NoSchedule
    key: node-role.kubernetes.io/master
---
apiServer:
  timeoutForControlPlane: 4m0s
apiVersion: kubeadm.k8s.io/v1beta1
certificatesDir: /etc/kubernetes/pki
clusterName: kubernetes
controlPlaneEndpoint: "10.20.0.100:6443"
controllerManager: {}
dns:
  type: CoreDNS
etcd:
  local:
    dataDir: /var/lib/etcd
imageRepository: k8s.gcr.io
kind: ClusterConfiguration
kubernetesVersion: v$k8s_version
networking:
  dnsDomain: cluster.local
  podSubnet: "$pod_network_cidr"
  serviceSubnet: $service_cidr
scheduler: {}
EOF
    if [ "$backup_master" != "true" ]; then
      echo "$(kubeadm init --config=kubeadm.cfg)" >> /vagrant/config/cert
    else

    # since master join ignores node-ip arg in kubelet config
    # modify default route in order to suggest kubelet choosing the correct IP
    ip route del `ip route | grep default`
    ip route add default via 10.20.0.100

    # copy certificates from the first master node
    mkdir -p /etc/kubernetes/pki/etcd
    cp /vagrant/certs/* /etc/kubernetes/pki/
    mv /etc/kubernetes/pki/etcd-ca.crt /etc/kubernetes/pki/etcd/ca.crt
    mv /etc/kubernetes/pki/etcd-ca.key /etc/kubernetes/pki/etcd/ca.key
    hash=$(awk 'END {print $NF}' /vagrant/config/cert)
    kubeadm join --token "${KUBEADM_TOKEN}"  10.20.0.100:6443 --discovery-token-ca-cert-hash "$hash" --experimental-control-plane
    fi
  else
    echo "$(kubeadm init --token-ttl 0 --kubernetes-version=v"${k8s_version}" --pod-network-cidr="${pod_network_cidr}" --apiserver-advertise-address="${KUBE_MASTER_IP}" --service-cidr="${service_cidr}" --token="${KUBEADM_TOKEN}")" >> /vagrant/config/cert
  fi
else
  echo "$(kubeadm init --token-ttl 0 --kubernetes-version=v"${k8s_version}" --pod-network-cidr="${pod_network_cidr}" --apiserver-advertise-address="${KUBE_MASTER_IP}" --service-cidr="${service_cidr}" --token="${KUBEADM_TOKEN}")" >> /vagrant/config/cert
fi

echo "Create folder to store kubernetes and network configuration"
mkdir -p /home/vagrant/.kube
sudo cp -i /etc/kubernetes/admin.conf /home/vagrant/.kube/config
sudo chown vagrant:vagrant -R /home/vagrant/.kube
sleep 2;

if  [ "$backup_master" != "true" ]; then
  # copy the certs into shared folder
  rm -rf /vagrant/certs
  mkdir /vagrant/certs
  cp /etc/kubernetes/pki/etcd/ca.crt /vagrant/certs/etcd-ca.crt
  cp /etc/kubernetes/pki/etcd/ca.key /vagrant/certs/etcd-ca.key
  cp /etc/kubernetes/admin.conf /vagrant/certs/
  cp /etc/kubernetes/pki/front-proxy-ca.* /vagrant/certs/
  cp /etc/kubernetes/pki/ca.* /vagrant/certs/
  cp /etc/kubernetes/pki/sa.* /vagrant/certs/
fi

applySTNScenario() {
  gw="10.130.1.254";
  if [ "${ip_version}" = "ipv6" ]; then
     gw="fe10::2:100";
  fi
  if [ "${dep_scenario}" = "nostn" ]; then

    # Generate node config for use with CRD
    cat > ${contiv_dir}/k8s/node-config/crd.yaml <<EOL
# Configuration for node config in the cluster
apiVersion: nodeconfig.contiv.vpp/v1
kind: NodeConfig
metadata:
  name: k8s-master
spec:
  mainVPPInterface:
    interfaceName: "GigabitEthernet0/8/0"
  gateway: $gw

---
EOL

    counter=1;
    until ((counter +1 > "${master_nodes}"))
    do

      # Generate node config for use with CRD
      cat <<EOL >> ${contiv_dir}/k8s/node-config/crd.yaml
# Configuration for node config in the cluster
apiVersion: nodeconfig.contiv.vpp/v1
kind: NodeConfig
metadata:
  name: k8s-master$counter
spec:
  mainVPPInterface:
    interfaceName: "GigabitEthernet0/8/0"
  gateway: $gw

---
EOL

    ((counter++))
    done

    counter=1;
    until ((counter > "${num_nodes}"))
    do

       # Generate node config for use with CRD
      cat <<EOL >> ${contiv_dir}/k8s/node-config/crd.yaml
# Configuration for node config in the cluster
apiVersion: nodeconfig.contiv.vpp/v1
kind: NodeConfig
metadata:
  name: k8s-worker$counter
spec:
  mainVPPInterface:
    interfaceName: "GigabitEthernet0/8/0"
  gateway: $gw

---
EOL

    ((counter++))
    done
  else
    curl -s https://raw.githubusercontent.com/contiv/vpp/master/k8s/stn-install.sh > /tmp/contiv-stn.sh
    chmod +x /tmp/contiv-stn.sh
    sudo /tmp/contiv-stn.sh
    # For use without CRD
    stn_config="--set contiv.stealInterface=enp0s8"

    # Generate node config for use with CRD
    cat > ${contiv_dir}/k8s/node-config/crd.yaml <<EOL
# Configuration for node config in the cluster
apiVersion: nodeconfig.contiv.vpp/v1
kind: NodeConfig
metadata:
  name: k8s-master
spec:
  mainVPPInterface:
    interfaceName: "GigabitEthernet0/8/0"

---
EOL

    counter=1;
    until ((counter +1 > "${master_nodes}"))
    do

      # Generate node config for use with CRD
      cat <<EOL >> ${contiv_dir}/k8s/node-config/crd.yaml
# Configuration for node config in the cluster
apiVersion: nodeconfig.contiv.vpp/v1
kind: NodeConfig
metadata:
  name: k8s-master$counter
spec:
  mainVPPInterface:
    interfaceName: "GigabitEthernet0/8/0"

---
EOL

    ((counter++))
    done

    counter=1;
    until ((counter > "${num_nodes}"))
    do
      # Generate node config for use with CRD
      cat <<EOL >> ${contiv_dir}/k8s/node-config/crd.yaml
# Configuration for node config in the cluster
apiVersion: nodeconfig.contiv.vpp/v1
kind: NodeConfig
metadata:
  name: k8s-worker$counter
spec:
  mainVPPInterface:
    interfaceName: "GigabitEthernet0/8/0"

---
EOL

      ((counter++))
    done
  fi
}

applyVPPnetwork() {
  # coredns config tweaks
  kubectl get configmap coredns -o yaml --export -n kube-system > /tmp/coredns-config.yaml
  if [[ $ip_version == "ipv6" ]]; then
    # set proper upstream dns server
    sed -i 's/\/etc\/resolv.conf/fe10::2:100/' /tmp/coredns-config.yaml
  fi
  # disable coredns loop detection plugin
  sed -i '/loop/d' /tmp/coredns-config.yaml
  kubectl apply -f /tmp/coredns-config.yaml -n kube-system

  # Deploy external etcd, nodeport etcd service and etcd secrets
  if [ ${master_nodes} -gt 1 ]; then
    kubectl apply -f ${contiv_dir}/k8s/multi-master/external_etcd.yaml
  fi

  helm_opts="${helm_extra_opts}"

  if [ "${image_tag}" != "latest" ]; then
    helm_opts="${helm_opts} --set vswitch.image.tag=${image_tag} --set cni.image.tag=${image_tag} --set ksr.image.tag=${image_tag} --set crd.image.tag=${image_tag}"
  fi

  if [ "${ip_version}" = "ipv6transport" ] || [ "${ip_version}" = "ipv6" ]; then
    helm_opts="$helm_opts --set contiv.ipamConfig.nodeInterconnectCIDR=fe10::2:0/119"
    helm_opts="$helm_opts --set contiv.ipamConfig.defaultGateway=fe10::2:100"
  fi
  if [ "${ip_version}" = "ipv6" ]; then
     if [ "${crd_disabled}" = "true" ]; then
        helm_opts="$helm_opts --set contiv.ipamConfig.podSubnetCIDR=2001::/48 --set contiv.ipamConfig.podSubnetOneNodePrefixLen=64"
        helm_opts="$helm_opts --set contiv.ipamConfig.vppHostSubnetCIDR=2002::/64 --set contiv.ipamConfig.vppHostSubnetOneNodePrefixLen=112"
        helm_opts="$helm_opts --set contiv.ipamConfig.vxlanCIDR=2005::/112"
     else
        helm_opts="$helm_opts --set contiv.ipamConfig.contivCIDR=fe10::/64"
     fi
     helm_opts="$helm_opts --set contiv.ipamConfig.serviceCIDR=2096::/110"
  else
    if [ "${crd_disabled}" = "false" ]; then
        helm_opts="$helm_opts --set contiv.ipamConfig.contivCIDR=10.128.0.0/14"
    fi
  fi
  if [ "${crd_disabled}" = "false" ]; then
    # Deploy contiv-vpp networking with CRD
     helm template --name vagrant $helm_opts $stn_config --set contiv.routeServiceCIDRToVPP=true --set contiv.tapv2RxRingSize=1024 --set contiv.tapv2TxRingSize=1024 --set contiv.crdNodeConfigurationDisabled=false --set contiv.ipamConfig.nodeInterconnectCIDR="" "${contiv_dir}"/k8s/contiv-vpp -f "${contiv_dir}"/k8s/contiv-vpp/values.yaml,"${contiv_dir}"/k8s/contiv-vpp/values-latest.yaml > "${contiv_dir}"/k8s/contiv-vpp/manifest.yaml
     kubectl apply -f ${contiv_dir}/k8s/contiv-vpp/manifest.yaml

    # Wait until crd agent is ready
    crd_ready="";
    while [ "$crd_ready" != "1" ];
    do
      echo "Waiting for crd agent to come up...";
      crd_ready=$(kubectl get daemonset contiv-crd -n kube-system --template={{.status.numberReady}});
      sleep 5;
    done;

      kubectl apply -f ${contiv_dir}/k8s/node-config/crd.yaml
  else
    if [ "${dep_scenario}" = "nostn" ] && [ "${ip_version}" = "ipv4" ]; then
       gateway_config="--set contiv.ipamConfig.defaultGateway=192.168.16.100"
    fi
    # Deploy contiv-vpp networking without CRD
    helm template --name vagrant $helm_opts $stn_config $gateway_config --set contiv.routeServiceCIDRToVPP=true --set contiv.tapv2RxRingSize=1024 --set contiv.tapv2TxRingSize=1024 "${contiv_dir}"/k8s/contiv-vpp -f "${contiv_dir}/"k8s/contiv-vpp/values.yaml,"${contiv_dir}"/k8s/contiv-vpp/values-latest.yaml > "${contiv_dir}"/k8s/contiv-vpp/manifest.yaml
    kubectl apply -f ${contiv_dir}/k8s/contiv-vpp/manifest.yaml
  fi

  echo "Schedule Pods on master"
  kubectl taint nodes --all node-role.kubernetes.io/master-

  echo "Deploy contiv UI"
  kubectl apply -f ${contiv_dir}/k8s/contiv-vpp-ui.yaml
}

applyCalicoNetwork() {
  echo "Deploy Calico"
  kubectl apply -f https://docs.projectcalico.org/v3.3/getting-started/kubernetes/installation/hosted/rbac-kdd.yaml
  kubectl apply -f https://docs.projectcalico.org/v3.3/getting-started/kubernetes/installation/hosted/kubernetes-datastore/calico-networking/1.7/calico.yaml

  echo "Schedule Pods on master"
  kubectl taint nodes --all node-role.kubernetes.io/master-
}

applyCalicoVPPNetwork() {
  echo "Deploy CalicoVPP"
  kubectl apply -f ${contiv_dir}/vagrant/calico-vpp/rbac-kdd.yaml
  kubectl apply -f ${contiv_dir}/vagrant/calico-vpp/calico.yaml
  kubectl apply -f ${contiv_dir}/vagrant/calico-vpp/calico-vpp.yaml

  echo "Label master with cni-type=calico"
  kubectl label nodes k8s-master cni-type=calico

  echo "Install calicoctl"
  wget --progress=bar:force https://github.com/projectcalico/calicoctl/releases/download/v3.3.2/calicoctl
  chmod +x calicoctl
  sudo mv calicoctl /usr/local/bin/
  sudo mkdir /etc/calico/
  sudo cp ${contiv_dir}/vagrant/calico-vpp/calicoctl.cfg /etc/calico/

  echo "Configure BGP"
  until sudo calicoctl apply -f ${contiv_dir}/vagrant/calico-vpp/bgp.yaml
  do
      sleep 1
      echo "retry..."
  done
}

if [ "$backup_master" != "true" ]; then
  stn_config=""
  export stn_config
  applySTNScenario

  if [ "${dep_scenario}" == 'calico' ]; then
    export -f applyCalicoNetwork
    su vagrant -c "bash -c applyCalicoNetwork"
  elif [ "${dep_scenario}" == 'calicovpp' ]; then
    export stn_config="${stn_config} --set contiv.nodeToNodeTransport=nooverlay --set contiv.ipamConfig.useExternalIPAM=true --set contiv.ipamConfig.podSubnetCIDR=10.10.0.0/16 --set vswitch.useNodeAffinity=true"
    export -f applyVPPnetwork
    su vagrant -c "bash -c applyVPPnetwork"
    export -f applyCalicoVPPNetwork
    su vagrant -c "bash -c applyCalicoVPPNetwork"
  else
    # nostn / stn
    export -f applyVPPnetwork
    su vagrant -c "bash -c applyVPPnetwork"
  fi
else
  echo "schedule pods on secondary master"
  su vagrant -c "kubectl taint node ${node_name} node-role.kubernetes.io/master-"
fi
