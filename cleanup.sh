#!/bin/bash
kubectl -n kube-system delete crd etcdclusters.etcd.database.coreos.com
kubectl -n kube-system delete deployment etcd-operator

kubectl -n kube-system delete secrets cilium-etcd-client-tls
kubectl -n kube-system delete secrets cilium-etcd-peer-tls
kubectl -n kube-system delete secrets cilium-etcd-server-tls
kubectl -n kube-system delete secrets cilium-etcd-secrets
kubectl -n kube-system delete -f ./cilium-etcd-operator.yaml
