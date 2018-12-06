#!/usr/bin/env python

import time

from kubernetes import config, client
from kubernetes.client import Configuration
from kubernetes.client.apis import core_v1_api
from kubernetes.client.rest import ApiException
from kubernetes.stream import stream

class Pod(object):
	_api = ""
	_name = "" 
	_conn = ""

	def __init__(self, name, image, host):
		self._api = core_v1_api.CoreV1Api()
		self._name = name + "-" + host
		resp = None
		try:
			resp = self._api.read_namespaced_pod(name=self._name,
							     namespace='default')
		except ApiException as e:
			if e.status != 404:
				print("Unknown error: %s" %e)
				exit(1)
		if not resp:
			print("Pod %s does not exist. Creating it..." % self._name)
			pod_manifest = {
 				'apiVersion': 'v1',
				'kind': 'Pod',
				'metadata': {
					'name': self._name
				},
			        'spec': {
					'containers': [{
						'image': image, 
						'name': 'sleep',
						"args": [
							"/bin/sh",
							"-c",
							"while true;do date;sleep 5; done"
						]
					}],
					'hostname': self._name,
					'subdomain': 'default-subdomain',
					'restartPolicy': 'Always',
					'affinity': {
						'nodeAffinity': {
							'requiredDuringSchedulingIgnoredDuringExecution': {
								'nodeSelectorTerms': [{
									'matchExpressions': [{
										'key': 'kubernetes.io/hostname',
										'operator': 'In',
										'values': [host] 
									}]
								}]
							}

						}
					},
					"tolerations": [{
						'operator': 'Exists'
					}]
				}
			}

			print pod_manifest

			resp = self._api.create_namespaced_pod(body=pod_manifest,
                        				       namespace='default')
    			while True:
				resp = self._api.read_namespaced_pod(name=self._name,
								     namespace='default')
				if resp.status.phase != 'Pending':
					break
				time.sleep(1)
			print("Done.")
 
 	def open_conn(self):
		self._conn = stream(	self._api.connect_get_namespaced_pod_exec,
					self._name,
					'default',
					command=['/bin/sh'],
					stderr=True,
					stdin=True,
					stdout=True,
					tty=False,
					_preload_content=False)
	
 	def close_conn(self):
		self._conn.close()

 	def send(self, command):
		self._conn.update(timeout=1)
		self._conn.write_stdin(command + "\n")
		while self._conn.is_open():
			self._conn.update(timeout=1)
                	if self._conn.peek_stdout():
                        	print("%s" % self._conn.read_stdout())
				break

	def get_name(self):
		return self._name

	def get_address(self):
                resp = None
		try:
                        resp = self._api.read_namespaced_pod_status(name=self._name,
								    namespace='default')
                except ApiException as e:
                        if e.status != 404:
                                print("Unknown error: %s" %e)
                                exit(1)

		return resp.status.pod_ip
