#!/usr/bin/env python

from kubernetes import config, client

from my_pod import Pod

if __name__ == '__main__':
	name = 'busyboxplus'
	config.load_kube_config()
	c = client.Configuration()
	c.assert_hostname = False
	client.Configuration.set_default(c)

	# list nodes
	v = client.CoreV1Api()
	hosts = v.list_node().items

	# delete pods 
	for i in range (0, len(hosts)):
		print "deleting client pod " + name + "-" + hosts[i].metadata.name
		Pod(name, hosts[i].metadata.name).delete()
