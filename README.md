# Important: for CoreDNS users

In order for the TLS certificates between etcd peers to work correctly, a DNS
reverse lookup on a pod IP must map back to pod name. If you are using CoreDNS,
check the CoreDNS ConfigMap and validate that `in-addr.arpa` and `ip6.arpa`
are listed as wildcards for the kubernetes block like this:

```
    kubectl -n kube-system edit cm coredns
    [...]
    apiVersion: v1
    data:
      Corefile: |
        .:53 {
            errors
            health
            kubernetes cluster.local in-addr.arpa ip6.arpa {
              pods insecure
              upstream
              fallthrough in-addr.arpa ip6.arpa
            }
            prometheus :9153
            proxy . /etc/resolv.conf
            cache 30
        }
```

The contents can look different than the above. The specific configuration that
matters is to make sure that `in-addr.arpa` and `ip6.arpa` are listed as
wildcards next to `cluster.local`.

You can validate this by looking up a pod IP with the `host` utility from any
pod:

```
    host 10.60.20.86
    86.20.60.10.in-addr.arpa domain name pointer cilium-etcd-972nprv9dp.cilium-etcd.kube-system.svc.cluster.local.
```

# Deployment

*Warning:* Deploying the cilium-etcd-operator will automatically overwrite the
Kubernetes secret `cilium-etcd-secrets`. If you have configured Cilium to use
an external etcd, it is likely using the same secret name so deploying the
cilium-etcd-operator will overwrite that secret.

If you already have a mechanism to generate certs and to avoid fresh certificate generation/overwrites to existing ones, set the following environment variable:

```
CILIUM_ETCD_OPERATOR_GENERATE_CERTS=false
```

```
kubectl apply -f https://raw.githubusercontent.com/cilium/cilium-etcd-operator/master/cilium-etcd-operator.yaml
```

# Verification

The cilium-etcd-operator will spawn an etcd-operator and create an etcd
cluster. This process can take a couple of seconds or minutes. After bootstrap,
a 3 node etcd cluster will be up:

```
kubectl -n kube-system get pods -l etcd_cluster=cilium-etcd
NAME                     READY   STATUS    RESTARTS   AGE
cilium-etcd-8k5czlw95m   1/1     Running   0          21h
cilium-etcd-mdwk9s99r5   1/1     Running   0          28h
cilium-etcd-zm52g4mqfv   1/1     Running   0          28h
```

It will also have created secrets to allow access to the etcd:

```
kubectl -n kube-system get secret | grep cilium-
cilium-etcd-client-tls                           Opaque                                3      28h
cilium-etcd-peer-tls                             Opaque                                3      28h
cilium-etcd-server-tls                           Opaque                                3      28h
cilium-token-nj9dm                               kubernetes.io/service-account-token   3      28h
```

# Troubleshooting

Check the status of the etcd-operator:

```
kubectl -n kube-system get pods -l io.cilium/app=etcd-operator
NAME                             READY   STATUS    RESTARTS   AGE
etcd-operator-547c5c7f84-qqr2t   1/1     Running   1          29h
```

Check the logs of the etcd-operator:
```
kubectl -n kube-system logs etcd-operator-547c5c7f84-qqr2t
[...]
```

Check for failing etcd cluster members:

```
kubectl -n kube-system get pods -l etcd_cluster=cilium-etcd
NAME                     READY   STATUS    RESTARTS   AGE
cilium-etcd-8k5czlw95m   1/1     Running   0          21h
cilium-etcd-mdwk9s99r5   1/1     Running   0          28h
cilium-etcd-zm52g4mqfv   1/1     Running   0          28h
```

Check the logs of individual etcd cluster member:

```
kubectl -n kube-system logs cilium-etcd-8k5czlw95m
```


# Termination

Terminating the cilium-etcd-operator will tear down the operator itself but
will keep the etcd cluster up an running. To tear down the etcd cluster itself:


```
kubectl -n kube-system delete etcdclusters.etcd.database.coreos.com cilium-etcd
```

If you want to clean all state, run the cleanup script:


```
./cleanup.sh

```
