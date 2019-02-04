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

package etcd_operator

import (
	"github.com/cilium/cilium-etcd-operator/pkg/defaults"

	apps_v1beta2 "k8s.io/api/apps/v1beta2"
	core_v1 "k8s.io/api/core/v1"
	apiextensions_v1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
)

var blockOwnerDeletion = true

// EtcdOperatorDeployment returns the etcd operator deployment that is
// for the given namespace.
func EtcdOperatorDeployment(namespace, ownerName, ownerUID, operatorImage, operatorImagePullSecret string) *apps_v1beta2.Deployment {
	nReplicas := int32(1)
	var secrets []core_v1.LocalObjectReference
	if operatorImagePullSecret != "" {
		imagePullSecret := core_v1.LocalObjectReference{Name: operatorImagePullSecret}
		secrets = append(secrets, imagePullSecret)
	}
	return &apps_v1beta2.Deployment{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      "etcd-operator",
			Namespace: namespace,
			OwnerReferences: []meta_v1.OwnerReference{
				{
					APIVersion:         "v1",
					Kind:               "Pod",
					Name:               ownerName,
					UID:                types.UID(ownerUID),
					BlockOwnerDeletion: &blockOwnerDeletion,
				},
			},
		},
		Spec: apps_v1beta2.DeploymentSpec{
			Replicas: &nReplicas,
			Selector: &meta_v1.LabelSelector{
				MatchLabels: defaults.CiliumLabelsApp,
			},
			Template: core_v1.PodTemplateSpec{
				ObjectMeta: meta_v1.ObjectMeta{
					Labels: defaults.CiliumLabelsApp,
				},
				Spec: core_v1.PodSpec{
					ServiceAccountName: "cilium-etcd-sa",
					Containers: []core_v1.Container{
						{
							Name:  "etcd-operator",
							Image: operatorImage,
							Command: []string{
								"etcd-operator",
								// Uncomment to act for resources in all
								// namespaces. More information in
								// doc/clusterwide.md
								// "-cluster-wide",
							},
							Env: []core_v1.EnvVar{
								{
									Name: "MY_POD_NAMESPACE",
									ValueFrom: &core_v1.EnvVarSource{
										FieldRef: &core_v1.ObjectFieldSelector{
											FieldPath: "metadata.namespace",
										},
									},
								},
								{
									Name: "MY_POD_NAME",
									ValueFrom: &core_v1.EnvVarSource{
										FieldRef: &core_v1.ObjectFieldSelector{
											FieldPath: "metadata.name",
										},
									},
								},
							},
						},
					},
					ImagePullSecrets: secrets,
				},
			},
		},
	}
}

// EtcdCRD returns the etcd CRD.
func EtcdCRD(ownerName, ownerUID string) *apiextensions_v1beta1.CustomResourceDefinition {
	return &apiextensions_v1beta1.CustomResourceDefinition{
		ObjectMeta: meta_v1.ObjectMeta{
			Name: "etcdclusters.etcd.database.coreos.com",
			OwnerReferences: []meta_v1.OwnerReference{
				{
					APIVersion:         "v1",
					Kind:               "Pod",
					Name:               ownerName,
					UID:                types.UID(ownerUID),
					BlockOwnerDeletion: &blockOwnerDeletion,
				},
			},
		},
		Spec: apiextensions_v1beta1.CustomResourceDefinitionSpec{
			Group: "etcd.database.coreos.com",
			Names: apiextensions_v1beta1.CustomResourceDefinitionNames{
				Kind:     "EtcdCluster",
				ListKind: "EtcdClusterList",
				Plural:   "etcdclusters",
				ShortNames: []string{
					"etcd",
				},
			},
			Scope:   apiextensions_v1beta1.NamespaceScoped,
			Version: "v1beta2",
			Versions: []apiextensions_v1beta1.CustomResourceDefinitionVersion{
				{
					Name:    "v1beta2",
					Served:  true,
					Storage: true,
				},
			},
			AdditionalPrinterColumns: []apiextensions_v1beta1.CustomResourceColumnDefinition{
				{
					JSONPath: ".metadata.creationTimestamp",
					Description: "CreationTimestamp is a timestamp representing the server time " +
						"when this object was created. It is not guaranteed to be set in happens-before " +
						"order across separate operations. Clients may not set this value. It is " +
						"represented in RFC3339 form and is in UTC. Populated by the system. " +
						"Read-only. Null for lists. More info: " +
						"https://git.k8s.io/community/contributors/devel/api-conventions.md#metadata",
					Name: "Age",
					Type: "date",
				},
			},
		},
	}
}
