#!/usr/bin/env bash
set -eu

getPodNames() {
        pods=`kubectl get pods | grep vpp-cnf`
        cnf1=`echo "${pods}" | grep -oE "vpp-cnf1\S*"`
        cnf2=`echo "${pods}" | grep -oE "vpp-cnf2\S*"`
        cnf3=`echo "${pods}" | grep -oE "vpp-cnf3\S*"`
}

checkReadiness() {
        echo "Checking pod readiness...(up to 30sec)"
        duration=0
        until [[ `kubectl get pods | grep vpp-cnf` != *"0/1"* ]];do
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
        node2=`kubectl get pods -o wide | grep vpp-cnf2 | grep -m 1 -oE "k8s-worker\S*"`
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
        #TODO: find out what else needs to be configured
        echo "extra sleep because 'something' is not ready"
        sleep 10
}

setupcnf1() {
        kubectl exec ${cnf1} -- /usr/bin/vppctl -s :5002 set int ip address memif0/1 192.168.187.1/30
        kubectl exec ${cnf1} -- /usr/bin/vppctl -s :5002 set int state memif0/1 up
        echo "Configured cnf1 with IP 192.168.187.1"
}

setupcnf2() {
        kubectl exec ${cnf2} -- /usr/bin/vppctl -s :5002 set int l2 xconnect memif0/1 memif0/2
        kubectl exec ${cnf2} -- /usr/bin/vppctl -s :5002 set int l2 xconnect memif0/2 memif0/1
        kubectl exec ${cnf2} -- /usr/bin/vppctl -s :5002 set int state memif0/1 up
        kubectl exec ${cnf2} -- /usr/bin/vppctl -s :5002 set int state memif0/2 up

        echo "Configured cnf2 with VPP xconnect."
}

setupcnf3() {
        kubectl exec ${cnf3} -- /usr/bin/vppctl -s :5002 set int ip address memif0/1 192.168.187.2/30
        kubectl exec ${cnf3} -- /usr/bin/vppctl -s :5002 set int state memif0/1 up
        echo "Configured cnf3 with IP 192.168.187.2"
}

testConnectivity() {
        echo "Pinging from CNF1:"
        there=`kubectl exec ${cnf1} -- /usr/bin/vppctl -s :5002 ping 192.168.187.2 source memif0/1 repeat 5`
        echo $there
        echo "Pinging from CNF3:"
        back=`kubectl exec ${cnf3} -- /usr/bin/vppctl -s :5002 ping 192.168.187.1 source memif0/1 repeat 5`
        echo $back
        loss_there=`echo ${there} | grep -oE "[[:digit:]]{1,3}% packet loss" | grep -oE "[[:digit:]]{1,3}"`
        loss_back=`echo ${back} | grep -oE "[[:digit:]]{1,3}% packet loss" | grep -oE "[[:digit:]]{1,3}"`
        if [ "${loss_there}" -gt "20" ] || [ "${loss_back}" -gt "20" ];then
                echo "Lost more than 1 packet. Exiting..."
                exit 1
        fi
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
node2=`kubectl get pods -o wide | grep vpp-cnf2 | grep -m 1 -oE "k8s-worker\S*"`
vswitch=`kubectl get pods -n kube-system -o wide | grep ${node2} | grep -oE "contiv-vswitch\S*"`
kubectl delete pod ${vswitch} -n kube-system
# Wait until vswitch is deleted
vswitch_present=1
until [[ "${vswitch_present}" -eq "0" ]];do
    vswitch_present=`kubectl get pods -n kube-system -o wide | grep ${vswitch} | wc -l`
done
checkReadiness
setupcnf2
testConnectivity

echo "VPP SFC tests done."
