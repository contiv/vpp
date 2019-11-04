#!/usr/bin/env bash
set -eu

getPodNames() {
        pods=`kubectl get pods | grep linux-cnf`
        cnf1=`echo "${pods}" | grep -oE "linux-cnf1\S*"`
        cnf2=`echo "${pods}" | grep -oE "linux-cnf2\S*"`
        cnf3=`echo "${pods}" | grep -oE "linux-cnf3\S*"`
}

checkReadiness() {
        echo "Checking pod readiness...(up to 30sec)"
        duration=0
        until [[ `kubectl get pods | grep linux-cnf` != *"0/1"* ]];do
                echo "Pods not ready, waiting..."
                duration=$((duration+5))
                if [ "${duration}" -gt "25" ];then
                        echo "Timed out waiting for pods to be ready."
                        exit 1
                fi
                sleep 5
        done
        echo "Pods ready."
        echo "Checking xconnnect configuration on VPP...(up to 30sec)"
        duration=0
        node2=`kubectl get pods -o wide | grep linux-cnf2 | grep -m 1 -oE "k8s-worker\S*"`

        vswitch=`kubectl get pods -n kube-system -o wide | grep ${node2} | grep -oE "contiv-vswitch\S*"`
        until [[ `kubectl exec ${vswitch} -n kube-system -- /usr/bin/vppctl show int address 2>error.log | grep -o "xconnect" | wc -l` == 4 ]];do
                echo "xconnect on VPP not configured, waiting..."
                duration=$((duration+5))
                if [ "${duration}" -gt "25" ];then
                        echo "Timed out waiting for xconnect configuration."
                        exit 1
                fi
                sleep 5
        done
        echo "VPP ready."
}

setupcnf1() {
        kubectl exec ${cnf1} -- ip address add 192.168.187.1/30 dev tap1
        kubectl exec ${cnf1} -- ip link set dev tap1 up
        echo "Configured cnf1 with IP 192.168.187.1"
}

setupcnf2() {
        kubectl exec ${cnf2} -- brctl addbr br1
        kubectl exec ${cnf2} -- brctl addif br1 tap1
        kubectl exec ${cnf2} -- brctl addif br1 tap2
        kubectl exec ${cnf2} -- ip link set dev br1 up
        kubectl exec ${cnf2} -- ip link set dev tap1 up
        kubectl exec ${cnf2} -- ip link set dev tap2 up
        echo "Configured cnf2 with linux bridge."
}

setupcnf3() {
        kubectl exec ${cnf3} -- ip address add 192.168.187.2/30 dev tap1
        kubectl exec ${cnf3} -- ip link set dev tap1 up
        echo "Configured cnf3 with IP 192.168.187.2"
}

testConnectivity() {
        kubectl exec ${cnf1} -- ping -c 20 -I tap1 192.168.187.2
        kubectl exec ${cnf3} -- ping -c 2 -I tap1 192.168.187.1
        echo "Connectivity verified."
}

getPodNames
checkReadiness
setupcnf1
setupcnf2
setupcnf3
testConnectivity

echo "Restarting cnf1 pod."
kubectl delete pod ${cnf1}
getPodNames
checkReadiness
setupcnf1
testConnectivity

echo "Restarting cnf2 and cnf3 pods."
kubectl delete pods ${cnf2} ${cnf3}
getPodNames
checkReadiness
setupcnf2
setupcnf3
testConnectivity

echo "Restarting vswitch on cnf2."
node=`kubectl get pods -o wide | grep linux-cnf2 | grep -m 1 -oE "k8s-worker\S*"`
vswitch=`kubectl get pods -n kube-system -o wide | grep ${node} | grep -oE "contiv-vswitch\S*"`
kubectl delete pod ${vswitch} -n kube-system
# Wait until vswitch is deleted
vswitch_present=1
until [[ "${vswitch_present}" -eq "0" ]];do
    vswitch_present=`kubectl get pods -n kube-system -o wide | grep ${vswitch} | wc -l`
done
checkReadiness
# tap interfaces will disappear along with vswitch, just cleanup the bridge
kubectl exec ${cnf2} -- ip link set dev br1 down
kubectl exec ${cnf2} -- brctl delbr br1
setupcnf2
testConnectivity

echo "Linux SFC tests done."
