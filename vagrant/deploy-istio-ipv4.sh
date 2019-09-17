#!/usr/bin/env bash

#install ingress controller
vagrant ssh k8s-master -c "kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/nginx-0.24.1/deploy/mandatory.yaml"
vagrant ssh k8s-master -c "kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/nginx-0.24.1/deploy/provider/baremetal/service-nodeport.yaml"

#install metallb load-balancer
vagrant ssh k8s-master -c "kubectl apply -f https://raw.githubusercontent.com/google/metallb/v0.8.1/manifests/metallb.yaml"
cat > layer2.yaml <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  namespace: metallb-system
  name: config
data:
  config: |
    address-pools:
    - name: my-ip-space
      protocol: layer2
      addresses:
      - 192.168.1.50-192.168.1.100
EOF

vagrant ssh k8s-master -c "kubectl apply -f /vagrant/layer2.yaml"

#install istio custom resource definitions
rm -rf istio-1.2.3
rm -f istio-1.2.3-linux.tar.gz
wget https://github.com/istio/istio/releases/download/1.2.3/istio-1.2.3-linux.tar.gz
tar -xzf istio-1.2.3-linux.tar.gz
cd istio-1.2.3
vagrant ssh k8s-master -c "kubectl create namespace istio-system"
vagrant ssh k8s-master -c "cd /vagrant/istio-1.2.3 && helm template install/kubernetes/helm/istio-init --name istio-init --namespace istio-system | kubectl apply -f -"

# Wait for istio CRDs
timer=0
while true;do
crd_istio=$(vagrant ssh k8s-master -c "kubectl get crds | grep 'istio.io\|certmanager.k8s.io' | wc -l" | tr -d '\r')
if [ ${crd_istio} -gt 10 ];then
    echo "istio crds found: $crd_istio"
    break
else
    echo "istio crds found: $crd_istio ...waiting for more"
fi
timer=$((timer+10))
if [ ${timer} -gt 180 ];then
  echo "Timed out waiting for istio CRDs after 3min."
  exit 1
fi
sleep 10
done

# generate istio yaml definitions
vagrant ssh k8s-master -c "cd /vagrant/istio-1.2.3 && helm template install/kubernetes/helm/istio --name istio --namespace istio-system > /home/vagrant/istio.yaml"
# optional - reduce minimum RAM for istio-pilot container
vagrant ssh k8s-master -c "sed -i -e 's/: 2048Mi/: 1024Mi/' istio.yaml"
# deploy istio proper
vagrant ssh k8s-master -c "kubectl apply -f istio.yaml"
