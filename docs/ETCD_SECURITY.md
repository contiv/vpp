# ETCD Security

By default, the access to Contiv-VPP ETCD is open to anybody. ETCD gets deployed
on the master node, on port `12379`, and is exposed using the NodePort service
on the port `32379` on each node.

To secure the access to ETCD, we recommend using the SSL/TLS certificates to authenticate
both client and server side and encrypt the communication.

In Contiv-VPP, this can be done using the Helm charts in [k8s/contiv-vpp folder](../k8s/contiv-vpp).

The prerequisite for that is generation of SSL certificates.


## Generate self-signed certificates
In order to secure ETCD, we need to create our own certificate authority
and generate the private keys and certificates for both ETCD server and ETCD clients. 

This guide uses CloudFlare's [cfssl](https://github.com/cloudflare/cfssl) tools to do this job.
It follows the steps described in this [CoreOS guide](https://github.com/coreos/docs/blob/master/os/generate-self-signed-certificates.md).

#### 1. Install cfssl
```
mkdir ~/bin
curl -s -L -o ~/bin/cfssl https://pkg.cfssl.org/R1.2/cfssl_linux-amd64
curl -s -L -o ~/bin/cfssljson https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64
chmod +x ~/bin/{cfssl,cfssljson}
export PATH=$PATH:~/bin
```

#### 2. Initialize a certificate authority
```
echo '{"CN":"CA","key":{"algo":"rsa","size":2048}}' | cfssl gencert -initca - | cfssljson -bare ca -
echo '{"signing":{"default":{"expiry":"43800h","usages":["signing","key encipherment","server auth","client auth"]}}}' > ca-config.json
```

#### 3. Generate server key + certificate
Replace the IP address `10.0.2.15` below with the IP address of your master node:
```
export ADDRESS=127.0.0.1,10.0.2.15
export NAME=server
echo '{"CN":"'$NAME'","hosts":[""],"key":{"algo":"rsa","size":2048}}' | cfssl gencert -config=ca-config.json -ca=ca.pem -ca-key=ca-key.pem -hostname="$ADDRESS" - | cfssljson -bare $NAME
```

#### 4. Generate client key + certificate
```
export ADDRESS=
export NAME=client
echo '{"CN":"'$NAME'","hosts":[""],"key":{"algo":"rsa","size":2048}}' | cfssl gencert -config=ca-config.json -ca=ca.pem -ca-key=ca-key.pem -hostname="$ADDRESS" - | cfssljson -bare $NAME
```

This produces the following files that will be needed in order to secure ETCD:
 - `ca.pem`: certificate of the certificate authority
 - `server.pem`: certificate of the ETCD server
 - `server-key.pem`: private key of the ETCD server
 - `client.pem`: certificate for the ETCD clients
 - `client-key.pem`: private key for the ETCD clients
 
 
## Distribute certificates and generate Contiv-VPP deployment yaml with secured ETCD access
There are two options for distributing the certificates to all nodes in a k8s cluster.
You can either do it manually, or embed the certificates into the deployment yaml file and 
distribute them as [k8s secrets](https://kubernetes.io/docs/concepts/configuration/secret/).

#### Option a) Distribute certificates manually
In this case, you need to copy the `ca.pem`, `client.pem` and `client-key.pem` files
into a specific folder (`/var/etcd/contiv-secrets` by default) on each worker node.
On the master node, you also need to add the `server.pem` and `server-key.pem` into that location.

Then you can generate the Contiv-VPP deployment YAML as follows:
```
cd k8s
helm template --name my-release contiv-vpp --set etcd.secureTransport=True > contiv-vpp.yaml
```
Then you can go ahead and deploy Contiv-VPP using this yaml file.

#### Option b) Embed the certificates into deployment the yaml and use k8s secret to distribute them
In this case, you need to copy all 5 generated files into the folder with helm definitions 
(`k8s/contiv-vpp`) and generate the Contiv-VPP deployment YAML as follows:
```
cd k8s
helm template --name my-release contiv-vpp --set etcd.secureTransport=True --set etcd.secrets.mountFromHost=False > contiv-vpp.yaml
```
Then you can go ahead and just deploy Contiv-VPP using this yaml file.


Please note that the path of the mount folder with certificates, as well as certificate 
file names can be customized using the config parameters of the Contiv-VPP chart, 
as described in [this README](../k8s/contiv-vpp/README.md).