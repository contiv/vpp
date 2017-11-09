### Using the Development image for testing with a specific VPP version (patch)

Start with building the images locally, [as described here](README.md). Once the build process finishes,
you should see a `dev-contiv-vswitch` image with some specific tag, e.g.:

```
$ sudo docker images | grep dev-contiv-vswitch
dev-contiv-vswitch                                       0.0.1-424-gd1a17e5   e6c9f12da183        About an hour ago   20.2GB
```

#### 1. Start the development container
```
sudo docker run -it dev-contiv-vswitch:0.0.1-424-gd1a17e5 bash

# if you are behind a proxy
export HTTPS_PROXY=http://proxy-wsa.esl.cisco.com:80/
export HTTP_PROXY=http://proxy-wsa.esl.cisco.com:80/
```

#### 2. Checkout the desired version of VPP / patch
```
cd /opt/vpp-agent/dev/vpp/
git checkout master
git pull
```

#### 3. Run debug build
(this will build the debug VPP binary we will actually use)
```
make build
```

If there haven't been any changes in the binary APIs since your last VPP update, 
you can continue with step 7.

#### 4. Build and install deb packages
(we need to install the new API JSON files into `/usr/share/vpp/api/`)
```
rm build-root/*.deb
make pkg-deb
yes | apt remove vpp vpp-plugins vpp-lib vpp-dev
cd build-root && dpkg -i *.deb
```

#### 5. Re-generate binary API bindings in Ligato vpp-agent
```
cd ~/go/src/github.com/ligato/vpp-agent/
make generate

# review the changes in APIs files, edit the code if needed
git diff

# build - must be succesfull
make
```

#### 6. Update & build Contiv-Agent
```
cd ~/go/src/github.com/contiv/vpp/
rm -rf vendor/github.com/ligato/vpp-agent/
cp -r ~/go/src/github.com/ligato/vpp-agent/ vendor/github.com/ligato/
rm -rf vendor/github.com/ligato/vpp-agent/vendor/
make
make install
```

#### 7. Commit the changes in the running container
```
sudo docker ps | grep vswitch
ba4e8b8b69d6        dev-contiv-vswitch:0.0.1-424-gd1a17e5   "bash"                   2 minutes ago       Up 2 minutes                            pensive_jepsen

sudo docker commit --change='CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]' ba4e8b8b69d6 dev-contiv-vswitch:0.0.1-424-gd1a17e5
```

(the CMD statement would be overwritten, so we need to specify it. If you don't want to start 
supervisord by container startup, you can modify it to your needs)

#### 8. Deploy the dev image
Modify the [contiv-vpp.yaml](../k8s/contiv-vpp.yaml) file to use your dev image instead of the
`contivvpp/vswitch` image. Also, disable the `readinessProbe` and `livenessProbe`. The example
of the diff is below.

Then deploy the network plugin using the modified YAML file:
```
kubectl apply -f contiv-vpp.yaml
```

```
diff --git a/k8s/contiv-vpp.yaml b/k8s/contiv-vpp.yaml
index df94c82..47a40b4 100644
--- a/k8s/contiv-vpp.yaml
+++ b/k8s/contiv-vpp.yaml
@@ -134,7 +134,7 @@ spec:
       initContainers:
       # This init container extracts/copies VPP LD_PRELOAD libs and default VPP config to the host.
       - name: vpp-init
-        image: contivvpp/vswitch
+        image: dev-contiv-vswitch:0.0.1-424-gd1a17e5
         imagePullPolicy: IfNotPresent
         command:
         - /bin/sh
@@ -160,7 +160,7 @@ spec:
         # Runs contiv-vswitch container on each Kubernetes node.
         # It contains the vSwitch VPP and its management agent.
         - name: contiv-vswitch
-          image: contivvpp/vswitch
+          image: dev-contiv-vswitch:0.0.1-424-gd1a17e5
           imagePullPolicy: IfNotPresent
           securityContext:
             privileged: true
@@ -169,17 +169,17 @@ spec:
             - containerPort: 5002
             # readiness + liveness probe
             - containerPort: 9191
-          readinessProbe:
-            httpGet:
-              path: /readiness
-              port: 9191
-            periodSeconds: 1
-          livenessProbe:
-            httpGet:
-              path: /liveness
-              port: 9191
-            periodSeconds: 1
-            initialDelaySeconds: 15
+#          readinessProbe:
+#            httpGet:
+#              path: /readiness
+#              port: 9191
+#            periodSeconds: 1
+#          livenessProbe:
+#            httpGet:
+#              path: /liveness
+#              port: 9191
+#            periodSeconds: 1
+#            initialDelaySeconds: 15
           env:
             - name: MICROSERVICE_LABEL
               valueFrom:
```