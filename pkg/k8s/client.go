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

package k8s

import (
	"fmt"
	"os"
	"time"

	"github.com/coreos/etcd-operator/pkg/generated/clientset/versioned"
	"github.com/sirupsen/logrus"
	apiExtClient "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	log = logrus.New()
)

var (
	// k8sCli is the default client.
	k8sCli                 *kubernetes.Clientset
	etcdClient             *versioned.Clientset
	apiextensionsclientset *apiExtClient.Clientset
)

// createConfig creates a rest.Config for a given endpoint using a kubeconfig file.
func createConfig(endpoint string) (*rest.Config, error) {
	// If the endpoint and the kubeCfgPath are empty then we can try getting
	// the rest.Config from the InClusterConfig
	if endpoint == "" {
		return rest.InClusterConfig()
	}

	config := &rest.Config{Host: endpoint}
	err := rest.SetKubernetesDefaults(config)

	return config, err
}

// createClient creates a new client to access the Kubernetes API
func createClient(config *rest.Config) (*kubernetes.Clientset, error) {
	cs, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}
	stop := make(chan struct{})
	timeout := time.NewTimer(time.Minute)
	defer timeout.Stop()
	wait.Until(func() {
		log.Info("Waiting for k8s api-server to be ready...")
		err = isConnReady(cs)
		if err == nil {
			close(stop)
			return
		}
		select {
		case <-timeout.C:
			log.WithError(err).WithField("ipaddress", config.Host).Error("Unable to contact k8s api-server")
			close(stop)
		default:
		}
	}, 5*time.Second, stop)
	if err == nil {
		log.WithField("ipaddress", config.Host).Info("Connected to k8s api-server")
	}
	return cs, err
}

// isConnReady returns the err for the controller-manager status
func isConnReady(c *kubernetes.Clientset) error {
	_, err := c.CoreV1().ComponentStatuses().Get("controller-manager", meta_v1.GetOptions{})
	return err
}

// Client returns the default Kubernetes client.
func Client() *kubernetes.Clientset {
	return k8sCli
}

func ExtensionsClient() *apiExtClient.Clientset {
	return apiextensionsclientset
}

func EtcdClient() *versioned.Clientset {
	return etcdClient
}

func getAPIServer() string {
	if os.Getenv("CILIUM_OPERATOR_BARE_METAL") == "" {
		return ""
	}
	if host := os.Getenv("KUBERNETES_SERVICE_HOST"); host != "" {
		if port := os.Getenv("KUBERNETES_SERVICE_PORT"); port != "" {
			return host + ":" + port
		}
	}
	return ""
}

func CreateDefaultClient() error {
	restConfig, err := createConfig(getAPIServer())
	if err != nil {
		return fmt.Errorf("unable to create k8s client rest configuration: %s", err)
	}

	k8sCli, err = createClient(restConfig)
	if err != nil {
		return fmt.Errorf("unable to create k8s client: %s", err)
	}

	etcdClient, err = versioned.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("unable to create etcd client: %s", err)
	}

	apiextensionsclientset, err = apiExtClient.NewForConfig(restConfig)
	if err != nil {
		return fmt.Errorf("unable to create apiExtClient: %s", err)
	}

	return nil
}
