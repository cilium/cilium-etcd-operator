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

package main

import (
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/cilium/cilium-etcd-operator/certs"
	"github.com/cilium/cilium-etcd-operator/cilium-etcd-cluster"
	"github.com/cilium/cilium-etcd-operator/etcd-operator"
	"github.com/cilium/cilium-etcd-operator/pkg/defaults"
	"github.com/cilium/cilium-etcd-operator/pkg/k8s"

	"github.com/coreos/etcd-operator/pkg/apis/etcd/v1beta2"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	apps_v1beta2 "k8s.io/api/apps/v1beta2"
	"k8s.io/api/core/v1"
	apiExt_v1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	meta_v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const (
	ciliumAnnotation = "io.cilium/etcd-operator-generated"
)

var (
	log = logrus.New()

	// cleanUPSig channel that is closed when the cilium-etcd-operator is
	// shutdown
	cleanUPSig = make(chan struct{})
	// cleanUPWg all cleanup operations will be marked as Done() when completed.
	cleanUPWg = &sync.WaitGroup{}
)

var (
	// RootCmd represents the base command when called without any subcommands
	RootCmd = &cobra.Command{
		Use:   "cilium-etcd-operator",
		Short: "Run the cilium etcd operator",
		Run: func(cmd *cobra.Command, args []string) {
			parseFlags()
			err := run()
			if err != nil {
				log.Error(err)
			}
		},
	}

	clusterDomain  string
	clusterSize    int
	gracePeriodSec int64
	etcdVersion    string
	gracePeriod    time.Duration
	namespace      string

	etcdCRD        *apiExt_v1beta1.CustomResourceDefinition
	etcdDeployment *apps_v1beta2.Deployment
	ciliumEtcdCR   *v1beta2.EtcdCluster
)

func init() {
	cobra.OnInitialize(func() {
		viper.SetEnvPrefix("cilium_etcd_operator")
	})

	flags := RootCmd.Flags()
	flags.StringVar(&clusterDomain,
		"cluster-domain", defaults.ClusterDomain, "Domain name used in cluster")
	viper.BindEnv("cluster-domain", "CILIUM_ETCD_OPERATOR_CLUSTER_DOMAIN")
	flags.IntVar(&clusterSize,
		"etcd-cluster-size", defaults.ClusterSize, "Size of the etcd cluster")
	viper.BindEnv("etcd-cluster-size", "CILIUM_ETCD_OPERATOR_ETCD_CLUSTER_SIZE")
	flags.StringVar(&etcdVersion,
		"etcd-version", defaults.ETCDVersion, "etcd version")
	viper.BindEnv("etcd-version", "CILIUM_ETCD_OPERATOR_ETCD_VERSION")
	flags.Int64Var(&gracePeriodSec,
		"grace-period-seconds", defaults.DefaultGracePeriodSecond, "Grace period, in seconds, before monitoring cluster health")
	viper.BindEnv("grace-period-seconds", "CILIUM_ETCD_OPERATOR_GRACE_PERIOD_SECONDS")
	flags.StringVar(&namespace,
		"namespace", defaults.DefaultNamespace, "Namespace where etcd-operator should be deployed")
	viper.BindEnv("namespace", "CILIUM_ETCD_OPERATOR_NAMESPACE")
	viper.BindPFlags(flags)
}

func parseFlags() {
	clusterDomain = viper.GetString("cluster-domain")
	clusterSize = viper.GetInt("etcd-cluster-size")
	etcdVersion = viper.GetString("etcd-version")
	gracePeriodSec = viper.GetInt64("grace-period-seconds")
	namespace = viper.GetString("namespace")

	etcdCRD = etcd_operator.EtcdCRD()
	etcdDeployment = etcd_operator.EtcdOperatorDeployment(namespace)
	ciliumEtcdCR = cilium_etcd_cluster.CiliumEtcdCluster(namespace, etcdVersion, clusterSize)
	gracePeriod = time.Duration(gracePeriodSec) * time.Second
	err := k8s.CreateDefaultClient()
	if err != nil {
		panic(err)
	}
}

func main() {
	handleCleanup(cleanUPWg, cleanUPSig, cleanUp)
	interruptCh := handleInterrupt()
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
	<-interruptCh
}

func handleInterrupt() <-chan struct{} {
	// Handle the handleOSSignals
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGQUIT, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM)
	interrupt := make(chan struct{})
	go func() {
		for s := range sig {
			log.WithField("signal", s).Info("Exiting due to signal")
			<-CleanUp()
			break
		}
		close(interrupt)
	}()
	return interrupt
}

func run() error {
	// generate all certificates that we will use
	m, err := certs.GenCertificates(namespace, clusterDomain)
	if err != nil {
		return err
	}
	// Deploying all secrets
	err = deploySecrets(namespace, m)
	if err != nil {
		return err
	}
	// We don't need to certificates so we can clean them up
	m = map[string]map[string][]byte{}

	err = deriveCiliumSecrets()
	if err != nil {
		return err
	}

	err = deployETCD()
	if err != nil {
		return err
	}

	log.Infof("Sleeping for %s to allow cluster to come up...", gracePeriod)
	select {
	case <-cleanUPSig:
		return nil
	case <-time.Tick(gracePeriod):
	}

	log.Info("Starting to monitor cluster health...")

	for {
		select {
		case <-cleanUPSig:
			return nil
		default:
		}
		time.Sleep(2 * time.Second)
		pl, err := k8s.Client().CoreV1().Pods(namespace).List(meta_v1.ListOptions{
			LabelSelector: "etcd_cluster=cilium-etcd",
			FieldSelector: "status.phase=Running",
		})
		if err != nil {
			log.Error(err)
			continue
		}
		if len(pl.Items) == 0 {
			log.Info("No running etcd pod found. Bootstrapping from scratch...")
			deployCiliumCR(true)
			log.Infof("Sleeping for %s to allow cluster to come up...", gracePeriod)
			select {
			case <-cleanUPSig:
				return nil
			case <-time.Tick(gracePeriod):
			}
			continue
		}
	}
}

func deployETCD() error {
	log.Info("Deploying etcd-operator CRD...")
	_, err := k8s.ExtensionsClient().ApiextensionsV1beta1().CustomResourceDefinitions().Get(etcdCRD.Name, meta_v1.GetOptions{})
	switch {
	case err == nil:
	case errors.IsNotFound(err):
		_, err := k8s.ExtensionsClient().ApiextensionsV1beta1().CustomResourceDefinitions().Create(etcdCRD)
		if err != nil {
			return fmt.Errorf("unable to create etcd-operator CRD: %s", err)
		}
	default:
		return fmt.Errorf("unable to get etcd-operator CRD: %s", err)
	}
	log.Info("Done!")

	log.Info("Deploying etcd-operator deployment...")
	_, err = k8s.Client().AppsV1beta2().Deployments(etcdDeployment.Namespace).Get(etcdDeployment.Name, meta_v1.GetOptions{})
	switch {
	case err == nil:
	case errors.IsNotFound(err):
		_, err := k8s.Client().AppsV1beta2().Deployments(etcdDeployment.Namespace).Create(etcdDeployment)
		if err != nil {
			return fmt.Errorf("unable to create etcd-operator deployment: %s", err)
		}
	default:
		return fmt.Errorf("unable to get etcd-operator deployment: %s", err)
	}
	log.Info("Done!")

	return deployCiliumCR(false)
}

func deployCiliumCR(force bool) error {
	log.Info("Deploying Cilium etcd cluster CR...")
	_, err := k8s.EtcdClient().EtcdV1beta2().EtcdClusters(ciliumEtcdCR.Namespace).Get(ciliumEtcdCR.Name, meta_v1.GetOptions{})
	switch {
	case force:
		k8s.EtcdClient().EtcdV1beta2().EtcdClusters(ciliumEtcdCR.Namespace).Delete(ciliumEtcdCR.Name, &meta_v1.DeleteOptions{})
		fallthrough
	case errors.IsNotFound(err):
		_, err := k8s.EtcdClient().EtcdV1beta2().EtcdClusters(ciliumEtcdCR.Namespace).Create(ciliumEtcdCR)
		if err != nil {
			return fmt.Errorf("unable to create Cilium etcd cluster CR: %s", err)
		}
	case err == nil:
	default:
		return fmt.Errorf("unable to get Cilium etcd cluster CR: %s", err)
	}
	log.Info("Done")
	return nil
}

func deriveCiliumSecrets() error {
	// For backwards compatibility we need to derive the secret that Cilium
	// uses, with the main secret.
	log.Info("Deriving etcd client from cilium-etcd-client-tls to cilium-etcd-secrets...")
	s, err := k8s.Client().CoreV1().Secrets(namespace).Get(defaults.CiliumEtcdClientTLS, meta_v1.GetOptions{})
	if err != nil {
		return err
	}
	s.ObjectMeta = meta_v1.ObjectMeta{
		Name:      defaults.CiliumEtcdSecrets,
		Namespace: namespace,
		Annotations: map[string]string{
			ciliumAnnotation: "true",
		},
	}

	log.Info("Updating cilium-etcd-secrets secret...")

	_, err = k8s.Client().CoreV1().Secrets(namespace).Get(defaults.CiliumEtcdSecrets, meta_v1.GetOptions{})
	if err == nil {
		k8s.Client().CoreV1().Secrets(namespace).Delete(defaults.CiliumEtcdSecrets, &meta_v1.DeleteOptions{})
	}
	_, err = k8s.Client().CoreV1().Secrets(namespace).Create(s)
	if err != nil {
		return err
	}
	log.Info("Done")

	return nil
}

func CleanUp() <-chan struct{} {
	close(cleanUPSig)
	exited := make(chan struct{})
	go func() {
		cleanUPWg.Wait()
		close(exited)
	}()
	return exited
}

func handleCleanup(wg *sync.WaitGroup, ch <-chan struct{}, f func()) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ch
		f()
	}()
}

func cleanUp() {
	log.Info("Deleting etcd-operator CRD...")
	err := k8s.ExtensionsClient().ApiextensionsV1beta1().CustomResourceDefinitions().Delete(etcdCRD.Name, &meta_v1.DeleteOptions{})
	if err != nil {
		log.Warning("Unable to delete etcd-operator CRD: %s", err)
	} else {
		log.Info("Done")
	}
	log.Info("Deleting etcd-operator deployment...")
	d := meta_v1.DeletePropagationForeground
	err = k8s.Client().AppsV1beta2().Deployments(etcdDeployment.Namespace).Delete(etcdDeployment.Name, &meta_v1.DeleteOptions{PropagationPolicy: &d})
	if err != nil {
		log.Warning("Unable to delete etcd-operator deployment: %s", err)
	} else {
		log.Info("Done")
	}
}

func deploySecret(name, namespace string, data map[string][]byte) error {
	s := v1.Secret{
		ObjectMeta: meta_v1.ObjectMeta{
			Name:      name,
			Namespace: namespace,
		},
		Data: data,
		Type: v1.SecretTypeOpaque,
	}
	_, err := k8s.Client().CoreV1().Secrets(namespace).Create(&s)
	return err
}

func deploySecrets(namespace string, secrets map[string]map[string][]byte) error {
	for secretName, secretData := range secrets {
		k8s.Client().CoreV1().Secrets(namespace).Delete(secretName, &meta_v1.DeleteOptions{})
		log.Infof("Deploying secret %s/%s...", namespace, secretName)
		err := deploySecret(secretName, namespace, secretData)
		if err != nil {
			return fmt.Errorf("unable to deploy secret %s/%s: %s", namespace, secretName, err)
		} else {
			log.Info("Done")
		}
	}
	return nil
}
