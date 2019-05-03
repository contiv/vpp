#!/usr/bin/env bash
set -ex

if [ "${ip_version}" == "ipv6" ]; then
   nat64_prefix='64:ff9b::'
   sysctl -w net.ipv6.conf.all.forwarding=1
   echo "Installing required packages"
   sudo -E apt-get update
   sudo -E apt-get install -y git build-essential linux-headers-$(uname -r) dkms \
       gcc make pkg-config libnl-genl-3-dev autoconf bind9

   echo "Downloading Jool"
   git clone https://github.com/NICMx/Jool.git
   cd /home/vagrant/Jool && git checkout v3.5.7
   echo "Installing Jool kernel modules"
  ( cd /home/vagrant/ && sudo dkms install Jool )

   echo "Compiling and installing Jool's user binaries"
   sudo chown -R vagrant:vagrant /home/vagrant/Jool
   ( cd /home/vagrant/Jool/usr && ./autogen.sh && ./configure )
   make -C /home/vagrant/Jool/usr
   sudo make install -C /home/vagrant/Jool/usr

   echo "Configuring Jool"
   sudo tee /etc/systemd/system/nat64.service << EOF
[Unit]
Description=Jool NAT64
After=network.target
[Service]
ExecStart=/root/nat64-setup.sh
[Install]
WantedBy=default.target
EOF

   sudo tee /root/nat64-setup.sh << EOF
#!/bin/bash
modprobe jool pool6=$nat64_prefix/96 disabled
ip4_address=\$(ip -o addr show dev enp0s3 | sed 's,/, ,g' | awk '\$3=="inet" { print $4 }')
jool -4 --add $ip4_address 7000-8000
jool -4 -d
jool -6 -d
jool --global --update --mtu-plateaus="9000,1450,1280"
jool --enable
EOF

   sudo chmod a+x /root/nat64-setup.sh

   sudo ip link set mtu 1450 dev enp0s3
   sudo ip link set mtu 1450 dev enp0s8
   sudo ip link set mtu 1450 dev enp0s9

   sudo ethtool --offload enp0s3 gro off
   sudo ethtool --offload enp0s8 gro off
   sudo ethtool --offload enp0s9 gro off

   sudo systemctl start nat64.service
   sudo systemctl enable nat64.service

   echo "Configuring bind"
   NS=`cat /etc/resolv.conf | grep nameserver | awk '{print $2}'`
   cat | sudo tee /etc/bind/named.conf.options << EOF
options {
  directory "/var/cache/bind";
  //dnssec-validation auto;
  auth-nxdomain no;
  listen-on-v6 { any; };
       forwarders {
         $NS;
       };
       allow-query { any; };
       # Add prefix for Jool's pool6
       dns64 $nat64_prefix/96 {
         exclude { any; };
       };
};
EOF

sudo service bind9 restart
systemctl status bind9


else

sed -i '/net.ipv4.ip_forward/s/^#//g' /etc/sysctl.conf
sysctl -p /etc/sysctl.conf

iptables --table nat --append POSTROUTING --out-interface enp0s3 -j MASQUERADE
iptables --append FORWARD --in-interface enp0s8 -j ACCEPT

# Load iptables rules on boot.
iptables-save >/etc/iptables-rules-v4.conf
cat<<'EOF'>/etc/network/if-pre-up.d/iptables-restore
#!/bin/sh
iptables-restore </etc/iptables-rules-v4.conf
EOF

chmod +x /etc/network/if-pre-up.d/iptables-restore
if [ "${node_os_release}" == "16.04" ] ; then
    sudo /sbin/ifdown enp0s8 && sudo /sbin/ifup enp0s8
fi

if [ "${dep_scenario}" == 'calicovpp' ]; then
    echo "Deploy bird BGP router"

    # generate BGP config into /etc/bird/bird.conf
    sudo mkdir /etc/bird
    sudo cp /vagrant/bird/bird.conf /etc/bird

    counter=2;
    until ((counter-1 > "${num_nodes}"))
    do
      sudo cat << EOL >> /etc/bird/bird.conf
protocol bgp {
        debug all;
        import all;
        export all;
        local as 63400;
        neighbor 192.168.16.$counter as 63400;
}
EOL
    ((counter++))
    done

    # install docker & deploy bird container
    sudo -E apt-get install -y docker.io
    sudo /vagrant/bird/run.sh
fi

# in case of nooverlay setup add explict routes to pod subnet on each node
if [[ $helm_extra_opts =~ contiv.useNoOverlay=(true|True) ]]; then
   cnt=1;

   if [[ $crd_disabled == "true" ]]; then

     pod_network="10.1"
     node_ip="192.168.16"

     until ((cnt > "$((num_nodes +1))"))
     do
      ip route add "$pod_network.$cnt.0/24"  via "$node_ip.$cnt"
      ((cnt++))
     done

   else

     pod_network="10.128"
     node_ip="10.130.0"

     until ((cnt > "$((num_nodes +1))"))
     do
      ip route add "$pod_network.$((cnt>>1)).$(((cnt<<7)&255))/25"  via "$node_ip.$cnt"
      ((cnt++))
     done
   fi

fi

# in case of ipv6 the source nat is not applied add routes to pod subnet
if [[ "$IP_VERSION" == "ipv6" ]]; then
   cnt=1;
   node_ip="fe10::2"
   pod_network="2001:0:0/64"

   until ((cnt > "$((num_nodes +1))"))
   do
     ip route add "$pod_network:$cnt::/64"  via "$node_ip:$cnt"
     ((cnt++))
   done
fi


if [ "${master_nodes}" -gt 1 ] ; then
   echo "Installing HAproxy"
   wget http://www.haproxy.org/download/1.9/src/haproxy-1.9.6.tar.gz
   tar -xzf haproxy-1.9.6.tar.gz
   cd haproxy-1.9.6
   make TARGET=generic
   make install
   mkdir /etc/haproxy

   cat > /etc/haproxy/haproxy.cfg <<EOF
frontend k8s-api
    bind 10.20.0.100:6443
    bind 127.0.0.1:6443
    mode tcp
    option tcplog
    default_backend k8s-api

backend k8s-api
    mode tcp
    option tcplog
    option tcp-check
    balance roundrobin
    default-server inter 10s downinter 5s rise 2 fall 2 slowstart 60s maxconn 250 maxqueue 256 weight 100
EOF

   counter=1
   until ((counter > "${master_nodes}"))
   do
       ip=$(( counter + 1 ))
       echo "       server apiserver$counter 10.20.0.$ip:6443 check">> /etc/haproxy/haproxy.cfg
       ((counter++))
   done

   echo "Configuring haproxy service"
   sudo tee /etc/systemd/system/haproxy.service << EOF
[Unit]
Description=HA proxy for k8s
[Service]
ExecStart=/root/haproxy.sh
[Install]
WantedBy=default.target
EOF

   sudo tee /root/haproxy.sh << EOF
#!/bin/bash
haproxy -f /etc/haproxy/haproxy.cfg
EOF

   sudo chmod a+x /root/haproxy.sh

   sudo systemctl start haproxy.service
   sudo systemctl enable haproxy.service

fi

fi # end of ipv4 case
