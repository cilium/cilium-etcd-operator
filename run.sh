#!/bin/sh

set -e

if [ ${DEBUG} ]; then
	set -x
fi

if [ -z "$INTERVAL" ]; then
	INTERVAL=2
fi

if [ -z "$GRACE_PERIOD" ]; then
	GRACE_PERIOD=300
fi

echo "Configuring kubectl..."
kubectl config set-cluster ${POD_NAMESPACE} --server=https://${KUBERNETES_PORT_443_TCP_ADDR} --certificate-authority=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
kubectl config set-context ${POD_NAMESPACE} --cluster=${POD_NAMESPACE}
kubectl config set-credentials user --token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
kubectl config set-context ${POD_NAMESPACE} --user=user

API_TOKEN_PATH=${API_TOKEN_PATH:-/var/run/secrets/kubernetes.io/serviceaccount/token}
KUBE_TOKEN=$(< ${API_TOKEN_PATH})
KUBERNETES_PORT_443_TCP_ADDR=${KUBERNETES_PORT_443_TCP_ADDR:-kubernetes}

echo "Deploying etcd-operator..."
kubectl apply -f etcd-operator/crd.yaml
kubectl apply -f etcd-operator/deployment.yaml

echo "Deploying cilium etcd cluster"
kubectl apply -f cilium-etcd-cluster/cilium-etcd-cluster.yaml

echo "Deployment complete."
echo "Sleeping for ${GRACE_PERIOD}s to allow cluster to come up..."
sleep ${GRACE_PERIOD}
echo "Starting to monitor health of cluster..."

while true; do
	NUM_ALIVE_ETCD_PODS=$(kubectl -n kube-system get pods -l etcd_cluster=cilium-etcd --field-selector=status.phase=Running | grep -v ^NAME | grep "1/1" | wc -l)
	if [ "${NUM_ALIVE_ETCD_PODS}" -eq "0" ]; then
		echo "No running etcd pod found. Bootstrapping from scratch..."
		kubectl delete -f cilium-etcd-cluster/cilium-etcd-cluster.yaml
		kubectl apply -f cilium-etcd-cluster/cilium-etcd-cluster.yaml
		echo "Sleeping for ${GRACE_PERIOD}s to allow cluster to come up..."
		sleep ${GRACE_PERIOD}
	fi

	sleep ${INTERVAL}
done

