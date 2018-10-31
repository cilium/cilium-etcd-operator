

# Deployment

*Warning:* Deploying the cilium-etcd-operator will automatically overwrite the
Kubernetes secret `cilium-etcd-secrets`. If you have configured Cilium to use
an external etcd, it is likely using the same secret name so deploying the
cilium-etcd-operator will overwrite that secret.

```
kubectl apply -f cilium-etcd-operator.yaml
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
