// Copyright 2018 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package defaults

var (
	CiliumLabelsApp = map[string]string{
		"io.cilium/app": "etcd-operator",
	}

	CiliumEtcdClientTLS = "cilium-etcd-client-tls"
	CiliumEtcdServerTLS = "cilium-etcd-server-tls"
	CiliumEtcdPeerTLS   = "cilium-etcd-peer-tls"
	CiliumEtcdSecrets   = "cilium-etcd-secrets"

	ETCDVersion = "3.3.11"

	ClusterSize = 3

	DefaultOperatorImage = "quay.io/coreos/etcd-operator:v0.9.3"

	DefaultBusyboxImage = "docker.io/library/busybox:1.28.0-glibc"

	DefaultNamespace = "kube-system"

	ClusterDomain = "cluster.local"

	ClusterName = "cilium-etcd"

	DefaultGracePeriodSecond int64 = 300

	ETCDEnvVarPrefix = "CILIUM_ETCD_META"
)
