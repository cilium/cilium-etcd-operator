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
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/signal"
	"strings"
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
			interruptCh := handleInterrupt()
			if preFlight {
				log.Println("Running in pre-flight mode...")
				handleCleanup(cleanUPWg, cleanUPSig, func() {})
			} else {
				if cleanUpOnExit {
					handleCleanup(cleanUPWg, cleanUPSig, cleanUp)
				}
				err := run()
				if err != nil {
					log.Error(err)
					log.Error("Error while creating etcd-operator deployment, restarting cilium-etcd-operator...")
					CleanUp()
					return
				}
			}
			<-interruptCh
		},
	}

	clusterDomain           string
	clusterSize             int
	etcdAffinityFile        string
	etcdNodeSelector        map[string]string
	quorumSize              int
	gracePeriodSec          int64
	etcdVersion             string
	gracePeriod             time.Duration
	namespace               string
	preFlight               bool
	etcdImageRepository     string
	generateCerts           bool
	cleanUpOnExit           bool
	busyboxImage            string
	operatorImage           string
	operatorImagePullSecret string

	etcdCRD        *apiExt_v1beta1.CustomResourceDefinition
	etcdDeployment *apps_v1beta2.Deployment
	ciliumEtcdCR   *v1beta2.EtcdCluster

	closeOnce sync.Once
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
	flags.BoolVar(&preFlight,
		"pre-flight", false, "Run in pre-flight mode.")
	viper.BindEnv("pre-flight", "CILIUM_ETCD_OPERATOR_PRE_FLIGHT")
	flags.StringVar(&etcdImageRepository,
		"etcd-image-repository", "quay.io/coreos/etcd", "Name of the repository that hosts etcd container images.")
	viper.BindEnv("etcd-image-repository", "CILIUM_ETCD_OPERATOR_ETCD_IMAGE_REPOSITORY")
	flags.BoolVar(&generateCerts,
		"generate-certs", true, "Generate and deploy TLS certificates")
	viper.BindEnv("generate-certs", "CILIUM_ETCD_OPERATOR_GENERATE_CERTS")
	flags.BoolVar(&cleanUpOnExit,
		"cleanup", true, "Cleanup resources on exit")
	viper.BindEnv("cleanup", "CILIUM_ETCD_OPERATOR_CLEANUP")
	flags.StringVar(&busyboxImage,
		"busybox-image", defaults.DefaultBusyboxImage, "Busybox image used for ETCD init container")
	viper.BindEnv("busybox-image", "CILIUM_ETCD_BUSYBOX_IMAGE")
	flags.StringVar(&operatorImage,
		"operator-image", defaults.DefaultOperatorImage, "Etcd Operator Image to be used")
	viper.BindEnv("operator-image", "CILIUM_ETCD_OPERATOR_IMAGE")
	flags.StringVar(&operatorImagePullSecret,
		"operator-image-pull-secret", "", "Secret to be used for Image Pull")
	viper.BindEnv("operator-image-pull-secret", "CILIUM_ETCD_OPERATOR_IMAGE_PULL_SECRET")
	flags.StringVar(&etcdAffinityFile, "etcd-affinity-file", "", "JSON file with the etcd affinity for etcd pods (JSON schema of k8s.io/api/core/v1/types.Affinity)")
	viper.BindEnv("etcd-affinity-file", "CILIUM_ETCD_OPERATOR_ETCD_AFFINITY_FILE")
	flags.StringToStringVar(&etcdNodeSelector, "etcd-node-selector", map[string]string{}, "etcd node selector")
	viper.BindEnv("etcd-node-selector", "CILIUM_ETCD_OPERATOR_ETCD_NODE_SELECTOR")

	viper.BindEnv("pod-name", "CILIUM_ETCD_OPERATOR_POD_NAME")
	viper.BindEnv("pod-uid", "CILIUM_ETCD_OPERATOR_POD_UID")
	viper.BindPFlags(flags)
}

func parseEtcdEnv() []v1.EnvVar {
	var etcdEnvVars []v1.EnvVar
	for _, envVar := range os.Environ() {
		if strings.HasPrefix(envVar, defaults.ETCDEnvVarPrefix) {
			var etcdEnvVarValue string

			etcdEnvVar := strings.TrimPrefix(envVar, defaults.ETCDEnvVarPrefix+"_")
			etcdEnvVarNameValue := strings.Split(etcdEnvVar, "=")
			etcdEnvVarName := etcdEnvVarNameValue[0]
			if len(etcdEnvVarNameValue) > 1 {
				etcdEnvVarValue = strings.Join(etcdEnvVarNameValue[1:], "=")
			}
			envVar := v1.EnvVar{
				Name:  etcdEnvVarName,
				Value: etcdEnvVarValue,
			}
			etcdEnvVars = append(etcdEnvVars, envVar)
		}
	}
	return etcdEnvVars
}

func parseFlags() {
	clusterDomain = viper.GetString("cluster-domain")
	clusterSize = viper.GetInt("etcd-cluster-size")
	quorumSize = (clusterSize / 2) + (clusterSize % 2)
	etcdImageRepository = viper.GetString("etcd-image-repository")
	etcdVersion = viper.GetString("etcd-version")
	gracePeriodSec = viper.GetInt64("grace-period-seconds")
	namespace = viper.GetString("namespace")
	ownerName := viper.GetString("pod-name")
	ownerUID := viper.GetString("pod-uid")
	preFlight = viper.GetBool("pre-flight")
	generateCerts = viper.GetBool("generate-certs")
	cleanUpOnExit = viper.GetBool("cleanup")
	operatorImage = viper.GetString("operator-image")
	operatorImagePullSecret = viper.GetString("operator-image-pull-secret")
	etcdAffinityFile = viper.GetString("etcd-affinity-file")
	// viper does not get the maps directly from the CLI with viper.GetStringMapString
	if len(etcdNodeSelector) == 0 {
		etcdNodeSelector = viper.GetStringMapString("etcd-node-selector")

	}
	etcdEnvVar := parseEtcdEnv()

	var affinity *v1.Affinity
	if etcdAffinityFile != "" {
		b, err := ioutil.ReadFile(etcdAffinityFile)
		if err != nil {
			log.Fatalf("Unable to read etcd-affinity file %q: %s", etcdAffinityFile, err)
		}
		affinity = &v1.Affinity{}
		err = json.Unmarshal(b, affinity)
		if err != nil {
			log.Fatalf("Unable to parse etcd-affinity file %q: %s", etcdAffinityFile, err)
		}
	}

	etcdCRD = etcd_operator.EtcdCRD()
	etcdDeployment = etcd_operator.EtcdOperatorDeployment(namespace, ownerName, ownerUID, operatorImage, operatorImagePullSecret)
	ciliumEtcdCR = cilium_etcd_cluster.CiliumEtcdCluster(namespace, etcdImageRepository, etcdVersion, clusterSize, etcdEnvVar, affinity, etcdNodeSelector, busyboxImage)
	gracePeriod = time.Duration(gracePeriodSec) * time.Second
}

func main() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
}

func handleInterrupt() <-chan struct{} {
	// Handle the handleOSSignals
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGQUIT, syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM)
	interrupt := make(chan struct{})
	go func() {
		for s := range sig {
			log.WithField("signal", s).Info("Exiting due to signal")
			CleanUp()
			break
		}
		close(interrupt)
	}()
	return interrupt
}

func run() error {
	err := k8s.CreateDefaultClient()
	if err != nil {
		panic(err)
	}

	err = ensureCerts()
	if err != nil {
		return err
	}
	err = deployETCD(false)
	if err != nil {
		return err
	}
	err = deployCiliumCR(false)
	if err != nil {
		return err
	}

	log.Infof("Sleeping for %s to allow cluster to come up...", gracePeriod)

	t := time.NewTicker(gracePeriod)
	for {
		select {
		case <-cleanUPSig:
			return nil
		case <-t.C:
			t.Stop()
			goto forloop
		case <-time.Tick(30 * time.Second):
			// in case the first etcd-operator deployment is not running, retry
			// it until we start monitoring cluster health.
			_, err := k8s.Client().AppsV1beta2().Deployments(etcdDeployment.Namespace).Get(etcdDeployment.Name, meta_v1.GetOptions{})
			if errors.IsNotFound(err) {
				err = deployETCD(false)
				if err != nil {
					return err
				}
			}
		}
	}
forloop:

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
			err := deployETCD(true)
			if err != nil {
				log.Error(err)
				continue
			}
			log.Info("No running etcd pod found. Bootstrapping from scratch...")
			err = deployCiliumCR(true)
			if err != nil {
				log.Error(err)
				continue
			}
			log.Infof("Sleeping for %s to allow cluster to come up...", gracePeriod)
			select {
			case <-cleanUPSig:
				return nil
			case <-time.Tick(gracePeriod):
			}
			continue
		}
		if len(pl.Items) < quorumSize {
			// https://github.com/coreos/etcd-operator/issues/1972
			// Etcd Operator doesn't do anything to bring back the cluster if the quorum is lost
			// The main constraints for the upstream being, restoring backup after quorum is lost
			// In case of Cilium, agents can back fill the etcd after cluster is up
			log.Info("Etcd cluster lost the quorum. Bootstrapping from scratch...")
			cleanUp()
			continue
		}
	}
}

func checkCerts() (bool, error) {
	log.Info("Checking existing certificates...")

	secrets := []string{
		defaults.CiliumEtcdClientTLS,
		defaults.CiliumEtcdServerTLS,
		defaults.CiliumEtcdPeerTLS,
		defaults.CiliumEtcdSecrets,
	}

	// FIXME: check if certs are valid: expiration date, subject fields and etc
	for _, secret := range secrets {
		_, err := k8s.Client().CoreV1().Secrets(namespace).Get(secret, meta_v1.GetOptions{})
		switch {
		case err == nil:
		case errors.IsNotFound(err):
			return false, nil
		default:
			return false, err
		}
	}
	return true, nil
}

func ensureCerts() error {
	if !generateCerts {
		valid, err := checkCerts()
		if err != nil {
			return err
		}
		if valid {
			log.Info("Reuse existing TLS certificates")
			return nil
		}
		log.Info("No valid certificates exists")
	}

	log.Info("Generating TLS certificates...")

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
	// We don't need certificates so we can clean them up
	m = map[string]map[string][]byte{}

	err = deriveCiliumSecrets()
	if err != nil {
		return err
	}

	return nil
}

func deployETCD(force bool) error {
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
	etcdDeplyServer, err := k8s.Client().AppsV1beta2().Deployments(etcdDeployment.Namespace).Get(etcdDeployment.Name, meta_v1.GetOptions{})
	switch {
	case err == nil && !force:
		if etcdDeplyServer.Status.AvailableReplicas != 0 && etcdDeplyServer.DeletionTimestamp == nil {
			etcdCpy := etcdDeployment.DeepCopy()
			etcdCpy.UID = etcdDeplyServer.UID
			_, err = k8s.Client().AppsV1beta2().Deployments(etcdDeployment.Namespace).Update(etcdDeployment)
			if err != nil {
				return fmt.Errorf("unable to update etcd-operator deployment: %s", err)
			}
			break
		}
		// If there are no available replicas running,
		// fallthrough to re-create etcd-deployment
		fallthrough
	case force:
		fg := meta_v1.DeletePropagationForeground
		k8s.Client().AppsV1beta2().Deployments(etcdDeployment.Namespace).Delete(etcdDeployment.Name, &meta_v1.DeleteOptions{PropagationPolicy: &fg})
		t := time.NewTicker(2 * time.Minute)
		for {
			// Wait until the deployment does not exist
			log.Info("Waiting for previous etcd-operator deployment to be removed...")
			_, err := k8s.Client().AppsV1beta2().Deployments(etcdDeployment.Namespace).Get(etcdDeployment.Name, meta_v1.GetOptions{})
			if errors.IsNotFound(err) {
				t.Stop()
				break
			}
			select {
			case <-time.Tick(time.Second):
			case <-t.C:
				return fmt.Errorf("Timeout waiting for etcd-operator deployment to be deleted: %s", err)
			}
		}
		log.Info("Done! Re-creating etcd-operator deployment...")
		fallthrough
	case errors.IsNotFound(err):
		_, err := k8s.Client().AppsV1beta2().Deployments(etcdDeployment.Namespace).Create(etcdDeployment)
		if err != nil {
			return fmt.Errorf("unable to create etcd-operator deployment: %s", err)
		}
	default:
		return fmt.Errorf("unable to get etcd-operator deployment: %s", err)
	}
	log.Info("Done!")

	return nil
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

func CleanUp() {
	closeOnce.Do(func() {
		close(cleanUPSig)
		cleanUPWg.Wait()
	})
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
		log.Warningf("Unable to delete etcd-operator CRD: %s", err)
	} else {
		log.Info("Done")
	}
	log.Info("Deleting etcd-operator deployment...")
	d := meta_v1.DeletePropagationForeground
	err = k8s.Client().AppsV1beta2().Deployments(etcdDeployment.Namespace).Delete(etcdDeployment.Name, &meta_v1.DeleteOptions{PropagationPolicy: &d})
	if err != nil {
		log.Warningf("Unable to delete etcd-operator deployment: %s", err)
	} else {
		log.Info("Done")
	}

	// Inetermittently the foreground cleanup is not working, causing the etcd pods lying around
	// Etcd operator not cleaning up the pods after quorum is lost
	// This additional safety check can make sure if any orphan pods and deletes them
	// Need to add Pods delete permissions in the cluster role binding
	pl, err := k8s.Client().CoreV1().Pods(namespace).List(meta_v1.ListOptions{
		LabelSelector: "etcd_cluster=cilium-etcd",
		FieldSelector: "status.phase=Running",
	})
	if err != nil {
		log.Warningf("Unable to find the etcd pods")
	} else {
		for _, p := range pl.Items {
			err = k8s.Client().CoreV1().Pods(namespace).Delete(p.Name, &meta_v1.DeleteOptions{})
			if err != nil {
				log.Warningf("Unable to delete the pods %s", p.Name)
				log.Error(err)
			} else {
				log.Info("Deleted the pod ", p.Name)
			}
		}
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
