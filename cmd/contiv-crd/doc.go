// Contiv-crd is an agent that start a custom resource for Kubernetes responsible
// to get telemetry information for every node
package main

// Flags are defined for the CRD executable as follows:
// -config-dir			default "."
// 						Location of the config files; can also be set via 'CONFIG_DIR' env variable.
//
// -etcd-config:		default "etcd.conf"
// 						Location of the "etcd" plugin config file; can also be set via "ETCD_CONFIG" env variable.
//
// -http-config:		default ="http.conf"
// 						Location of the "http" plugin config file; can also be set via "HTTP_CONFIG" env variable.
//
// -http-port:			default "9191":
// 						Configure "http" server port
//
// -kube-config: 		default ="/etc/kubernetes/admin.conf"
// 						Path to the kubeconfig file to use for the client connection to K8s cluster
//
// -microservice-label: default "vpp1": microservice label
// 						also set via 'MICROSERVICE_LABEL' env variable.
//
// -verbose: 			default 'false'
// 						output & logging verbosity; true = log debug, false = log error.
