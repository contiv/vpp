#!/usr/bin/env python

from kubernetes import config, client

from my_pod import Pod

if __name__ == '__main__':
	pod = []
	config.load_kube_config()
	c = client.Configuration()
	c.assert_hostname = False
	client.Configuration.set_default(c)

	# list nodes
	v = client.CoreV1Api()
	hosts = v.list_node().items
 
	# create pods
	for i in range (0, len(hosts)):
		pod.append(Pod('busyboxplus', 'radial/busyboxplus:curl', hosts[i].metadata.name))
		pod[i].open_conn()

	# test pods
	for i in range (0, len(hosts)):
		print pod[i].get_name(), "(", pod[i].get_address(), ")"
		for j in range (0, 10):
			pod[i].send('wget -O - 10.96.1.1/server_addr 2>/dev/null')

	# close pods
	for i in range(0, len(hosts)):
		pod[i].close_conn()
