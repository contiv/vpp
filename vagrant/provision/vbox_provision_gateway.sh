#!/usr/bin/env bash
set -ex

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
if [ "#{node_os_release}" == "16.04" ] ; then
    sudo /sbin/ifdown enp0s8 && sudo /sbin/ifup enp0s8
fi

if [ "#{dep_scenario}" == 'calicovpp' ]; then
    echo "Deploy bird BGP router"

    # generate BGP config into /etc/bird/bird.conf
    sudo mkdir /etc/bird
    sudo cp /vagrant/bird/bird.conf /etc/bird

    counter=2;
    until ((counter-1 > "#{num_nodes}"))
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
