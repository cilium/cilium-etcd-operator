# v2.0.6

###**Breaking changes**:
 - Change default to only generate TLS certificates if they do not exist (https://github.com/cilium/cilium-etcd-operator/pull/57)
 - Change default to leave etcd cluster running if `cilium-etcd-operator` is shut down (https://github.com/cilium/cilium-etcd-operator/pull/57)

###**Features**:
 - Add `--etcd-image-repository` to set etcd image repository (https://github.com/cilium/cilium-etcd-operator/pull/43/files)
 - Allow for a persistent `etcd` cluster between `cilium-etcd-operator` restarts (https://github.com/cilium/cilium-etcd-operator/pull/45)
 - Provide option, `--busybox-image`, to set the busybox image used in the init container of etcd pod.
 - Bump go to `1.12.1` (https://github.com/cilium/cilium-etcd-operator/pull/49)
 - Bump etcd-operator to `v0.9.4` (https://github.com/cilium/cilium-etcd-operator/pull/49)
 - Bump default etcd to `3.3.12` (https://github.com/cilium/cilium-etcd-operator/pull/49)
 - Add the ability to run an already deployed CRD and CR (Check README.md for "Deployment with an existing EtcdCluster custom resource")
 - `cilium-etcd-operator version` will report the version being used  (https://github.com/cilium/cilium-etcd-operator/pull/61)
 
###**Bug fixes**:
 - Fix missing delete RBAC permissions in k8s descriptor (https://github.com/cilium/cilium-etcd-operator/pull/40)
 - Add quotes to all environment variables set in `cilium-etcd-operator.yaml` (https://github.com/cilium/cilium-etcd-operator/pull/58)