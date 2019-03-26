#!/usr/bin/env bash
# Short version skips installing docker, kubernetes, helm, etc.

set -ex

echo Args passed: [[ $@ ]]

# --------------------------------------------------------
# ---> Build Contiv/VPP-vswitch Development Image <---
# --------------------------------------------------------

if [ "${dep_env}" = "dev" ]; then
    # wait for apt auto-update to finish so we don't get conflicts
    #TODO: disable apt daily services in the vagrant box
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

echo "Exporting Kube Master IP and Kubeadm Token..."
echo "export KUBEADM_TOKEN=$(kubeadm token generate)" >> /vagrant/config/init

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

# Based on kubernetes version, disable hugepages in Kubelet
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
if [ $split_k8s_version -gt 10 ] ; then
  if [ "${node_os_release}" == "16.04" ] ; then
    sed -i '1s/.*/KUBELET_EXTRA_ARGS=--node-ip='"$KUBE_MASTER_IP"' --feature-gates HugePages=false/' /etc/default/kubelet
  else
    sed -i '1s/.*/KUBELET_EXTRA_ARGS=--node-ip='"$KUBE_MASTER_IP"' --feature-gates HugePages=false --resolv-conf=\/run\/systemd\/resolve\/resolv.conf/' /etc/default/kubelet
  fi
  systemctl daemon-reload
  systemctl restart kubelet
  if [ "${dep_scenario}" != 'calico' ] && [ "${dep_scenario}" != 'calicovpp' ]; then
    echo "$(kubeadm init --token-ttl 0 --kubernetes-version=v"${k8s_version}" --pod-network-cidr="${pod_network_cidr}" --apiserver-advertise-address="${KUBE_MASTER_IP}" --service-cidr="${service_cidr}" --token="${KUBEADM_TOKEN}")" >> /vagrant/config/cert
  else
    echo "$(kubeadm init --token-ttl 0 --kubernetes-version=v"${k8s_version}" --pod-network-cidr="${pod_network_cidr}" --apiserver-advertise-address="${KUBE_MASTER_IP}" --service-cidr="${service_cidr}" --token="${KUBEADM_TOKEN}")" >> /vagrant/config/cert
  fi
else
  sed -i '4 a Environment="KUBELET_EXTRA_ARGS=--node-ip='"$KUBE_MASTER_IP"' --feature-gates HugePages=false"' /etc/systemd/system/kubelet.service.d/10-kubeadm.conf
  systemctl daemon-reload
  systemctl restart kubelet
  echo "$(kubeadm init --token-ttl 0 --kubernetes-version=v"${k8s_version}" --pod-network-cidr="${pod_network_cidr}" --apiserver-advertise-address="${KUBE_MASTER_IP}" --service-cidr="${service_cidr}" --token="${KUBEADM_TOKEN}")" >> /vagrant/config/cert
fi

echo "Create folder to store kubernetes and network configuration"
mkdir -p /home/vagrant/.kube
sudo cp -i /etc/kubernetes/admin.conf /home/vagrant/.kube/config
sudo chown vagrant:vagrant -R /home/vagrant/.kube
sleep 2;

applySTNScenario() {
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
  gateway: "10.130.1.254"

---
EOL
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
  gateway: "10.130.1.254"

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
  helm_opts="${helm_extra_opts}"

  if [ "${image_tag}" != "latest" ]; then
    helm_opts="${helm_opts} --set vswitch.image.tag=${image_tag} --set cni.image.tag=${image_tag} --set ksr.image.tag=${image_tag} --set crd.image.tag=${image_tag}"
  fi

  if [ "${ip_version}" = "ipv6transport" ] || [ "${ip_version}" = "ipv6" ]; then
    helm_opts="$helm_opts --set contiv.ipamConfig.nodeInterconnectCIDR=fe10:f00d::/90"
  fi
  if [ "${ip_version}" = "ipv6" ]; then
    helm_opts="$helm_opts --set contiv.ipamConfig.podSubnetCIDR=2001::/48 --set contiv.ipamConfig.podSubnetOneNodePrefixLen=64"
    helm_opts="$helm_opts --set contiv.ipamConfig.vppHostSubnetCIDR=2002::/64 --set contiv.ipamConfig.vppHostSubnetOneNodePrefixLen=112"
    helm_opts="$helm_opts --set contiv.ipamConfig.vxlanCIDR=2005::/112 --set contiv.ipamConfig.serviceCIDR=2096::/110"
  fi
  if [ "${crd_disabled}" = "false" ]; then
    # Deploy contiv-vpp networking with CRD
    helm template --name vagrant $helm_opts $stn_config --set contiv.routeServiceCIDRToVPP=true --set contiv.tapv2RxRingSize=1024 --set contiv.tapv2TxRingSize=1024 --set contiv.crdNodeConfigurationDisabled=false --set contiv.ipamConfig.contivCIDR=10.128.0.0/14 --set contiv.ipamConfig.nodeInterconnectCIDR="" "${contiv_dir}"/k8s/contiv-vpp -f "${contiv_dir}"/k8s/contiv-vpp/values.yaml,"${contiv_dir}"/k8s/contiv-vpp/values-latest.yaml > "${contiv_dir}"/k8s/contiv-vpp/manifest.yaml
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

stn_config=""
export stn_config
applySTNScenario

if [ "${dep_scenario}" == 'calico' ]; then
  export -f applyCalicoNetwork
  su vagrant -c "bash -c applyCalicoNetwork"
elif [ "${dep_scenario}" == 'calicovpp' ]; then
  export stn_config="${stn_config} --set contiv.useL2Interconnect=true --set contiv.ipamConfig.useExternalIPAM=true --set contiv.ipamConfig.podSubnetCIDR=10.10.0.0/16 --set vswitch.useNodeAffinity=true"
  export -f applyVPPnetwork
  su vagrant -c "bash -c applyVPPnetwork"
  export -f applyCalicoVPPNetwork
  su vagrant -c "bash -c applyCalicoVPPNetwork"
else
  # nostn / stn
  export -f applyVPPnetwork
  su vagrant -c "bash -c applyVPPnetwork"
fi
