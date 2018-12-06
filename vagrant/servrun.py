#!/usr/bin/env python

from kubernetes import config, client

from my_pod import Pod

if __name__ == '__main__':
	service = "nginx"
	namespace = "default"
	hostname = service + "." + namespace + ".svc.cluster.local"
	url = "/server_addr"
	command = "wget -O - " + hostname + url + " 2>dev/null"
	iterations = 10
	pod = []
	config.load_kube_config()
	c = client.Configuration()
	c.assert_hostname = False
	client.Configuration.set_default(c)

	# list nodes
	v = client.CoreV1Api()
	hosts = v.list_node().items

	# get service IP
	service_ip = v.read_namespaced_service_status(service, namespace).spec.cluster_ip

	# open connections
	for i in range (0, len(hosts)):
		pod.append(Pod('busyboxplus', hosts[i].metadata.name))
		pod[i].open_conn()

	# test pods
	for i in range (0, len(hosts)):
		print "client pod " +  pod[i].get_name(), "(", pod[i].get_address(), ")"
		print "testing service " + service + " ( " + service_ip + " )"
		print iterations, "iterations.  Responses: \n" 
		for j in range (0, iterations):
			pod[i].send(command)

	# close connections
	for i in range(0, len(hosts)):
		pod[i].close_conn()
