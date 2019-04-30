# External ETCD instance

By default an instance of etcd is deployed as a part of contiv-vpp in its yaml file.
However, you can also point contiv to use a custom, in this tutorial called external, etcd instance.
The aim of this document is to describe required steps to achieve this.

## Deploying etcd instance

Your custom etcd instance can be deployed at any location accessible from all k8s nodes.
For the sake of simplicity in this tutorial, the etcd will be deployed in the k8s cluster

```yaml
apiVersion: apps/v1beta2
kind: StatefulSet
metadata:
  name: my-etcd
  namespace: kube-system
  labels:
    k8s-app: my-etcd
spec:
  serviceName: my-etcd
  selector:
    matchLabels:
      k8s-app: my-etcd
  updateStrategy:
    type: RollingUpdate
  template:
    metadata:
      labels:
        k8s-app: my-etcd
      annotations:
        # Marks this pod as a critical add-on.
        scheduler.alpha.kubernetes.io/critical-pod: ''
    spec:
      tolerations:
        # We need this to schedule on the master no matter what else is going on, so tolerate everything.
        - key: ''
          operator: Exists
          effect: ''
        # This likely isn't needed due to the above wildcard, but keep it in for now.
        - key: CriticalAddonsOnly
          operator: Exists
      # Only run this pod on the master.
      nodeSelector:
        node-role.kubernetes.io/master: ""
      hostNetwork: true

      containers:
        - name: my-etcd
          image: quay.io/coreos/etcd:v3.3.11
          imagePullPolicy: IfNotPresent
          env:
            - name: ETCDCTL_API
              value: "3"
            - name: ETCDCTL_CACERT
              value: /var/contiv/etcd-secrets/ca.pem
          command:
            - /bin/sh
          args:
            - -c
            - /usr/local/bin/etcd --name=contiv-etcd --data-dir=/var/etcd/contiv-data
              --client-cert-auth --trusted-ca-file=/var/contiv/etcd-secrets/ca.pem
              --cert-file=/var/contiv/etcd-secrets/server.pem --key-file=/var/contiv/etcd-secrets/server-key.pem
              --peer-client-cert-auth --peer-trusted-ca-file=/var/contiv/etcd-secrets/ca.pem
              --peer-cert-file=/var/contiv/etcd-secrets/server.pem --peer-key-file=/var/contiv/etcd-secrets/server-key.pem
              --advertise-client-urls=https://0.0.0.0:12379 --listen-client-urls=https://0.0.0.0:12379 --listen-peer-urls=https://0.0.0.0:12380
              --cipher-suites TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
          volumeMounts:
            - name: var-etcd
              mountPath: /var/etcd/
            - name: etcd-secrets
              mountPath: /var/contiv/etcd-secrets
              readOnly: true
          resources:
            requests:
              cpu: 100m
      volumes:
        - name: etcd-secrets
          secret:
            secretName: my-etcd-secrets
            items:
            - key: caCert
              path: ca.pem
            - key: serverCert
              path: server.pem
            - key: serverKey
              path: server-key.pem
        - name: var-etcd
          hostPath:
            path: /var/etcd
            
---

apiVersion: v1
kind: Service
metadata:
  name: my-etcd
  namespace: kube-system
spec:
  type: NodePort
  selector:
    k8s-app: my-etcd
  ports:
    - port: 12379
      nodePort: 31379

---
apiVersion: v1
kind: Secret
type: Opaque
metadata:
  name: my-etcd-secrets
  namespace: kube-system
data:
  caCert: |-
    LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUREakNDQWZhZ0F3SUJBZ0lVR1dyM2pBNkZiUXVDb0ZyOW5EeDJvTSt2TGo4d0RRWUpLb1pJaHZjTkFRRUwKQlFBd0RURUxNQWtHQTFVRUF4TUNRMEV3SGhjTk1UZ3hNREF5TVRBME16QXdXaGNOTWpNeE1EQXhNVEEwTXpBdwpXakFOTVFzd0NRWURWUVFERXdKRFFUQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCCkFMVmI1SGxXNFZoSkVUdXRJZlRRMGc5b1h0RFdIWnp3czcyenVyRDhjT2F1VXRleE50Q2xYR09pd3BuQVFDN0MKT29YY29aNWp6MlIwUGt0SVorZ0dsa3dzVncvZEhWTTNSbmd4cnVXNlg2SGsxbEdHNGIrcStSUmwvUUIxR1ArMApaNDVSMy8rVU13Kzc5M09TcHNaZDU0RmpvcGJEWWU5bDJTRDg5VzVqTlY5K2xSMjQ5VkZhcGdqckRpL3dvbGNmCnNyVW8ybWo1V2E5YjJwWXZvQ3BJckhEVDh6VHNmbW9HNGFYVlRxdklJbkRaOUV6SHZTS2M2VnQ4Uk5MTVhuLzUKWkRBSkFzRTROOG0vSlcxdWlUa2NLTEV0bXJ3WmxPMHZIcS9Sb3NjMENPK1dZSWVFOWhZODIyRXhrVDF6cmhrUgpyaExGN2tNa1BjN1BXc1RydDBDNXdIY0NBd0VBQWFObU1HUXdEZ1lEVlIwUEFRSC9CQVFEQWdFR01CSUdBMVVkCkV3RUIvd1FJTUFZQkFmOENBUUl3SFFZRFZSME9CQllFRklmakhadnVRMEYrVGh0bHh4RUZDUERsM1RnMU1COEcKQTFVZEl3UVlNQmFBRklmakhadnVRMEYrVGh0bHh4RUZDUERsM1RnMU1BMEdDU3FHU0liM0RRRUJDd1VBQTRJQgpBUUJRczZuTHp1bkxLMk9GcHB3SXgwQ1FYVnRub3lOWlEvWmNVU1dsL2tHSFRKZS9LaDAyb0dDZmJuTTNWTFZNClBqWkZhRWxZRzdEWnI3MUdQbzJyTTRtMC9JWDBPbUJ4ZWppbm1CQ2hkRlR2cys0WUxnL3JhYis5L3E0VkhGS3cKWjhqZit6RjN1UFUwaWNhbWl5R3U2MWZWN3hJWFdBc0xLeW5FSjFmM29jNVllZ0hqakMwSHJheE0zVFU4Q2lqdQo5VFNsMC92dkJmbkZWRWFlcGl5K3VwNHZ6M2ZnTy9ncDd4NHgwOWZ2Uld0RG1OeWlmbGcyaGlEM0Q2Tk5RS0FCCm16RDhnV0d0ZVBvZTBwVCt3dGNBZHFjWHFpMWJ5eGI1K0VsNHpWRS9XZ0hnaUNxQnJBUWk3dE9lZlJ3Z250cDAKc2IyL0FzSEVVZVoxdCtnT3J6V0JDK3lJCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0K
  serverCert: |-
    LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURSRENDQWl5Z0F3SUJBZ0lVUXV4Wi9RNXhqNG16WnVkdHBvY2VROW5vMm9nd0RRWUpLb1pJaHZjTkFRRUwKQlFBd0RURUxNQWtHQTFVRUF4TUNRMEV3SGhjTk1UZ3hNREF5TVRBME5EQXdXaGNOTWpNeE1EQXhNVEEwTkRBdwpXakFSTVE4d0RRWURWUVFERXdaelpYSjJaWEl3Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLCkFvSUJBUURHcUY5ZjZkQ1J1T2ZIdTZRVGVFZFFqa0hJbXRkNmJMQmc2SEoxUk8rTFBaRHN3b1o3eFNWZTV2RlMKeFZsRkJOcEdrVWNOOE1ZdHF6RHRHUXd0Mi9YeXAvMmk5VGFGZk1pWUVoT0ErYkMwUGJtMm4xYXp0Y1g0QUFZcgp5K2d1SDI4YWJldStCZlhuNzUzUnNpRmlsTnFoQkJ2bWVjaFZoWDhocUVjWFJMOG5kS2lONWVwZ2podDRnTXdZCit5U2VRK2FKbk1ZdkhEZitkYXhxejY5eHJQSmk1aEdWRXVOMFZ2bWpySEVZQWxqMnZvYnpXcElGT1R1amRPSFAKbUU1WnJIY2pGYkVCK1NpRXR3bFYrZGorTlRkMlB3Qk9sY2pEc3U3eTdwcDNnSmNlajVuS1pTU051M2ZxT0FuKwpvQm1uSDA5bVNuM1pjMmZPaHFidUFGL0plQmV2QWdNQkFBR2pnWmN3Z1pRd0RnWURWUjBQQVFIL0JBUURBZ1dnCk1CMEdBMVVkSlFRV01CUUdDQ3NHQVFVRkJ3TUJCZ2dyQmdFRkJRY0RBakFNQmdOVkhSTUJBZjhFQWpBQU1CMEcKQTFVZERnUVdCQlNrekFWckdGMnNEY0ZjVk1kSE5SbTVrczBpaFRBZkJnTlZIU01FR0RBV2dCU0g0eDJiN2tOQgpmazRiWmNjUkJRanc1ZDA0TlRBVkJnTlZIUkVFRGpBTWh3Ui9BQUFCaHdRS0FBSVBNQTBHQ1NxR1NJYjNEUUVCCkN3VUFBNElCQVFBM2doNEs4eHFMejU5K3dEZEhKazNabTV5YUwwVGRlRGcvdU5hZkppTFE4M0xIeHR1OGkxMVEKRVY1MUZPQUcvdVJ2NmdNeVJ4SFhCMkw5YU9YbS9uNm1jZS9pZmVFZmJvdmUybTZ6dkNUTXU2RTVKTGJML0hUOQpnT1hkNCtDR3RBTnRPZzd1cnFwb3RhTkhQMnIvZFN0NTlFQVJZRWQ5MmdtclYwWS84dStRY1l1cDBNaUhqcUhGCjk4MXVFZ0lBY0F1QWJNYzI5bVB5RDhSRG1RazRzenpEYmF4L0k4dHVNTmJHcUtxMWRTdnVaanJJZmw3cU9sWXUKQlZZdlMvSWlMbTFhYkdGTEwxTE9Ib3YyeGxxNVY3blJOWFJLNW81NHB0WGhoMFRrdjVTcjRZQlFwTTVvUDBYawpHVmtxZWhFKys3elF5TkNIaWpwd2hjM3d6UEFvWUlBZgotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==
  serverKey: |-
    LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVBeHFoZlgrblFrYmpueDd1a0UzaEhVSTVCeUpyWGVteXdZT2h5ZFVUdml6MlE3TUtHCmU4VWxYdWJ4VXNWWlJRVGFScEZIRGZER0xhc3c3UmtNTGR2MThxZjlvdlUyaFh6SW1CSVRnUG13dEQyNXRwOVcKczdYRitBQUdLOHZvTGg5dkdtM3J2Z1gxNSsrZDBiSWhZcFRhb1FRYjVubklWWVYvSWFoSEYwUy9KM1NvamVYcQpZSTRiZUlETUdQc2tua1BtaVp6R0x4dzMvbldzYXMrdmNhenlZdVlSbFJMamRGYjVvNnh4R0FKWTlyNkc4MXFTCkJUazdvM1RoejVoT1dheDNJeFd4QWZrb2hMY0pWZm5ZL2pVM2RqOEFUcFhJdzdMdTh1NmFkNENYSG8rWnltVWsKamJ0MzZqZ0ovcUFacHg5UFprcDkyWE5uem9hbTdnQmZ5WGdYcndJREFRQUJBb0lCQUZMTjJidEw1V0RvTnN4ZApIVDMwVTUxelBsNVVsRjUyTVdxaldSb2lXc3FxSmQ5YUVkNURSWmx5SDhMRmViazRGWmQyZEt5TjRMMG1ieVZVCjNHdTlGSjVKZ1lKTVBhYVVaYlJsVEhYbEhjOXpMeGE5QWRHMGdja21rV3Z0K1dCSVAvSS9RUlVhdk80cFJab2oKYXFFQnRNT0t4K3BnZHEyWEVHL0NDYWZjUXVVNWtncjAzZ2hhYnZNMnRBWEhBVzg3NDhjRlpyV05oSkgwWllwcgo0Nnl3S2plM2h6aVhXQStUbGw0dER6RnZMSHpmQStXKzFnTFpKSlJZSzBzcm1sWHRidGt3dStINXI1OFVnVmJLClFHclBKWkdrYjFpYUxIWHdUL1FhZkF1azZoRGxkM0ZoLzFobGJoSVFVR3VZeWN6T1JvOFkvUDY3cFZKREN5UnUKVDQzdkxza0NnWUVBNDJEMmlwOFFTYXh0U01rU1NNYit1bE5saUpCYmNqcUhqVTBrcWhid0hHMm5mUE1Hbi93ZgpSY0hPYndBTHREa3psN1pEbUVONXYrVFNJb0cvRmdTblFnamUwZ0hVMkN6bDZuL3UvcWZZNGIwTXZzMi9XcS80Cm12Sk95akZtZnRsVXRYZksxYko1TkplZVNpTEYxcnJrY3hNWlMybDdZZ3R3ZHR5a0g5dGp3ZE1DZ1lFQTM2bm4KZTc4TThBRXlaaWN1VmpPa1B2bHBnSmtzeEp1MVREdFZnODZ6bGtleVp5bGR6R2Z4VXRWdnlYeERQeHRIMkxGeQp2a0JGUWNKSW1PZjBJN1creXR5Y1BjNE9NM1A2RnFsVFhnUGJ4aElFMTRmUWdiTW9PbW9hOFphUXk5M2kwejFyClRhbWhOYzNzNFF0QVhucUk1TEN2b0YzOUJyODJmTVRLbEhvWnpUVUNnWUVBMEdvbE1XU2hRbFpwQ1drOGVEYm0KYjVWWG9MaHBDYWY2Ylp0RE95Q3hUKzEyc3dIemxaczhjdTAxTWV0Qnp4MExYRWsxWmhDYlBUZ1pJSVg2eDh6VwpIcUlRMHovWWY1bVAyTVVSSkp4bklHcnZqc2o2Vjc2cVNpUkY4ZkViK0xOdWdMTmYyVWF3OEhMMUpSRUFkRlYwClpzSWYwazdLU0ZFaDhlRkdFdWsrWS84Q2dZRUExNG13WGZ3NngzOGZ4bm16bWJhaWJWMkZZanc2ZkMxaGhWa1kKaTdEQ04reFg3RHBjL2dLYytLcGUwOWhBSmF4d2pFNVV1U3JPa3hSYlNaOGVFdHV1UldoYjJPT2RvOC84RGFLWAppRjVIaUpVTXZYZFFZK3oyczNSVkNzT0NQalJSeGlmR0pFMTM0WlhVMVBvMnlkVmozcDYyWU9DeVdiSWpIQkc0CjkyVERRSkVDZ1lBZXFrTHNWYVJ4TG9FNzFHVG1GdDh1VmtseDN4NXJXK2wvbVVNN1dFVXZ3Rkp4cjJZNk1pT0kKWUNmdmNtY3J6ZGlwMTBRSlc2RVBKS3RzaC9BWVREQmJXUEdrQU9PWTZxYWdNVlNqdFZZYnIweis0RmFWZGZ5UQoyMm9DY3FHbG91Q1F3ZjJhWVlCdnlING9QNm56Zm1yZk1rTWZDZFFWQXVSVU5GTEhnU3QwWWc9PQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=
  clientCert: |-
    LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURPakNDQWlLZ0F3SUJBZ0lVVzNZSjVjRW10KzJaamdIT3BESEN2Y3JLZ3FNd0RRWUpLb1pJaHZjTkFRRUwKQlFBd0RURUxNQWtHQTFVRUF4TUNRMEV3SGhjTk1UZ3hNREF5TVRBME5EQXdXaGNOTWpNeE1EQXhNVEEwTkRBdwpXakFSTVE4d0RRWURWUVFERXdaamJHbGxiblF3Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLCkFvSUJBUURJTTVkNDllZUl4SjlQTnFoMFdBN0lOWmFCalVaWi9PRmpocjM3c1FEK3dnMVZkbFdPQ0pqTCsvRnkKTFhQMXF4MVNRSTNic2hSc3E4NC9INisvdUVTMEpyemZzZkRGNU5qODNmdFZHUjNhWWJLalhWZU9YenQ1bVorbwpjWWpBb3VLNGp6ZUxDT2h1WnJYSFRXWmloTVBRdStGMnVNY24yQnVWazFUQVJ4MnVIU2p6cmwrTjJYb2RrbXZlClRQa3MzOW1hWWRyZ013L0svcGNucE5aQ3pjSUlndHh0bitsa2s2WFE4Q2s4RzlBMnhvYWV1T2p2RGdVSmk4SGoKZEdKVkV0V201aGJ6UUtDbXJ1bGpVNlk2Ry9QdTBKR2NyU1Z1dURVTHZwMDF3ZDlVaW1MWnFqK2d1c1VRenBDTQpOeDJrSjdjOXlodUtpY1FJcXVMR2Z4RkVlcHBCQWdNQkFBR2pnWTB3Z1lvd0RnWURWUjBQQVFIL0JBUURBZ1dnCk1CMEdBMVVkSlFRV01CUUdDQ3NHQVFVRkJ3TUJCZ2dyQmdFRkJRY0RBakFNQmdOVkhSTUJBZjhFQWpBQU1CMEcKQTFVZERnUVdCQlNlYUtVcG5VU2RaZHZVdDR3L25KeFZRS094b3pBZkJnTlZIU01FR0RBV2dCU0g0eDJiN2tOQgpmazRiWmNjUkJRanc1ZDA0TlRBTEJnTlZIUkVFQkRBQ2dnQXdEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBR1BoCnY4TTN6L1RUNk0zM1B1Z0VaR0Uvc1k5UHFEaW9PNzdNTm0zWXpIMW9tem5USWZycU9qR2pmZ2JYQThXM2hjNDUKcGFFSnc0Rm41b0lsKzlzNkNCY2dXc1FHVElpYWJYY1FtVTZzanlQOHkwR3hOaGNiY29yVzVMcjJDd1lBYnJnSQpJZTFGK01sNnExVjZ2bzArczBkUzEydFhDRnRzZzBPWmVhRkpuanhtcERUZE44Wlc0RGNBVE5jOHVWcWZNUXMyCmp2K3VOckV1YkJYSkphZHFyT291anZYQTRXOGZadjhrZjBNZnQ1dzBtKzFmQkN5b1dDdHlIS1NncHZDTGNpR0MKUkUycFROV1hVOXE3L3BmblVjbWp2NFRsSFFpUXE5aXJlQWlCenVTWktYMy9GdHRCTlFndVp6a3ExQXErOFMvRQphY2pzYm84aXdpN1ljSEJoQ20wPQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==
  clientKey: |-
    LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVBeURPWGVQWG5pTVNmVHphb2RGZ095RFdXZ1kxR1dmemhZNGE5KzdFQS9zSU5WWFpWCmpnaVl5L3Z4Y2kxejlhc2RVa0NOMjdJVWJLdk9QeCt2djdoRXRDYTgzN0h3eGVUWS9OMzdWUmtkMm1HeW8xMVgKamw4N2VabWZxSEdJd0tMaXVJODNpd2pvYm1hMXgwMW1Zb1REMEx2aGRyakhKOWdibFpOVXdFY2RyaDBvODY1ZgpqZGw2SFpKcjNrejVMTi9abW1IYTRETVB5djZYSjZUV1FzM0NDSUxjYlovcFpKT2wwUEFwUEJ2UU5zYUducmpvCjd3NEZDWXZCNDNSaVZSTFZwdVlXODBDZ3BxN3BZMU9tT2h2ejd0Q1JuSzBsYnJnMUM3NmROY0hmVklwaTJhby8Kb0xyRkVNNlFqRGNkcENlM1Bjb2Jpb25FQ0tyaXhuOFJSSHFhUVFJREFRQUJBb0lCQUNTL3c2aENpMVBCcy9TWQpkZWVWV25GSjFPekhBQWo0c0c3U2h3RXlocG85Q0xHTlhUc0xQUEVFdUZkYkhKUVY2dlgwUDVYNlpHRm1VQitxCk0xcWYrb3lQSjlCd0cyQllGN1NqRXNXV0xMS3ZpRmtRZzBmeEZ6dkZCVmVvTDVBYzFqMUduTTE2dngrMDN0MU0KeWVSL3Rtb1VjdGlXSm9pYjFNUnFIUDZHajE0c1ROREUwcFhJODFsajJEOWJsSzVmQ3Vac2s0TjRQR2FodjBYRQpyNHRxaHhHWFFtckI0OTQxZ0JhT0tGaGNtY205MmdPS094TW03QVdRdFU5M1RDbHpVSUpXZEJ6NmExNzRldFNHCncxRDlPc29oczlmc1NZWWREeGhRcURXeTBpZ2x4K3A1SURwd2pxMkxkTGs1N3Q0bFQwVisrakNPdlJXSERJV1AKanA4MnRhRUNnWUVBOGk2VGxpekxtMU1Wb0VwRjRNTVd3aVB0S2Z1SjlEbFJCVHpYVFh4OWt2ZnlOMWNzM0xRMQoyeFp5TnppWUxGS1lRUGJHVUxNdG5jdk5XdTZtc3pqOXE3YnRmeC9ZRUNhTkRhdisvZ3BzNG9KVHBaWWxSZTc3ClIzRTFGdDZJVmpyR2FSSS9JcHN1ajBoeHRQQy95QVNwQm9RWUE4dldqd25pOFRYVEpWbjhFVzBDZ1lFQTA1L1UKWFBjV3lLY0NaazFBN3hhV0NPc2Y2WW81c0FzWmEzUDV1Zmpmang3bW5jODlVMEJ5UWMrWXZUcGFzYXh2T1dsZworNkFRUWpRUktjc2Z2NFdrcllxSGl4ekZZWWJuQzFIVlJ3YkZsazkrZEdXRndiMm1tZERaY1JoNEQwWEdMLzdQClNRbkplUnhmdENPd0JkSWpTSVZNZHl6SW4xa0JocytkMUlpMGU2VUNnWUVBcTNmQXRPWVlibXUvOXhJL01XalAKTnp0NmttdnUrOFNORWJsRzh5eStPQTFuS0RtSG9PZlM3Y0NSczNsVmZLUXArbXorY21xNlZHdlVoSnBOMnJ6eQpGZDdaZmxWTWcvclhpYU9LVWRHTjBEM1gvWGcyQWJLM3BKaUpyeHgxeVIrcUZRQi9SUUE4VWVSSDVZVkRNOW5nCjFxVTEzNUkxNG1ac2tMMjhOa2preUcwQ2dZRUFpZ28rbnVsNkRpYUtkU3E5U1hlbEpHb2lwZGJKTEdFQkVzdFMKd1JGcTJsT2d3SjJXOWdBYXgzemZ0OGNoczdXejAzSStsY1BoOXgwNWVOYUxmZ1Z4MXRWKzlxb3N3aUlhQVpNKwptSmI5T2IvZXo1UU5mTVAxc1cyKytIdXFqT1BKbERNVkNTSitMaWJvOG5zNDdZTVdDczhRZ3NoT2tVcWdxVXd5Ck9wbDFpUlVDZ1lBYWx6MGZBbW9SVVp1cUxPV2NPdVp4bjB6TFZ4cHJHTlNkREVpWkJzemRnUjltNmE2eHRrYkoKb0lZNW9yQ3A0VUR0U1pUdVRrTHJIa1dkRVlJNUhuYlB0aG9KQlpuWXFTVzB3N2h2WFQ2aUZod2pJUTAxRnoyZQpOUVVaa3YvaUoyb0wyblZwL0k2eTdLZnNNQ3BNek1Pdmo0amdYSlEzYWlTRmRvZ1VkcGplNHc9PQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=
                        
```

There is a nodeport service set up, that allows to access etcd at port 31397 on each node.
The etcd uses certificates in order to secure access.  

## Modification helm values

The value `etcd.useExternalInstance` denoting whether to deploy own contiv
 etcd or use external one must be set to `true`. The connection settings to
 external etcd are defined in `etcd.externalInstance` (other values except 
 in etcd section are ignored). Minimal config must contain definition of endpoints
 `etcd.exteralInstance.endpoints` where external etcd can be accessed.
 If external etcd instance is secured by using of certificates, values must also
 define secret name `etcd.externalInstance.secretName` in `kube-system` namespace.
 The secret must contain the following elements:
  - `caCert` certification authority used for validation of etcd server certificate
  - `clientCert` client certificate used for access the external etcd instance
  - `clientKey` corresponding key to `clientCert`

Modified values corresponding to instance deployed above
```yaml
...
etcd:
  useExternalInstance: true
  externalInstance:
    secretName: my-etcd-secrets
    endpoints:
      - 127.0.0.1:31379
```
 
 ## Deploy contiv-vpp
 
 Once values are modified you can proceed by deploying contiv-vpp as describe in the
 [README](../../k8s/README.md).

 Please, note: [bug report script](../../scripts/contiv-vpp-bug-report.sh) doesn't read data from external etcd instance
  and the data is not auto-compacted by contiv/vpp either.