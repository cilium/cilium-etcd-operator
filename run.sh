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

ANNOTATION="io.cilium/etcd-operator-generated=true"

trap cleanup EXIT

function cleanup {
	kubectl delete -f etcd-operator/crd.yaml || true
	kubectl delete -f etcd-operator/deployment.yaml || true
	kubectl delete -f cilium-etcd-cluster/cilium-etcd-cluster.yaml || true
}

function deriveCiliumMasterSecret {
	echo "Deriving main secret from cilium-etcd-client-tls..."
	kubectl get secret -n kube-system cilium-etcd-client-tls -o yaml > secret.yaml
	sed -i 's/name: cilium-etcd-client-tls/name: cilium-etcd-secrets/g' secret.yaml

	kubectl -n kube-system get secret cilium-etcd-secrets > /dev/null 2>&1 && {
		kubectl -n kube-system delete secret cilium-etcd-secrets || true
	}

	kubectl -n kube-system apply -f secret.yaml
	rm secret.yaml

	kubectl -n kube-system annotate secret cilium-etcd-secrets io.cilium/etcd-operator-generated=true
}

echo "Configuring kubectl..."
kubectl config set-cluster ${POD_NAMESPACE} --server=https://${KUBERNETES_PORT_443_TCP_ADDR} --certificate-authority=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
kubectl config set-context ${POD_NAMESPACE} --cluster=${POD_NAMESPACE}
kubectl config set-credentials user --token=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
kubectl config set-context ${POD_NAMESPACE} --user=user

API_TOKEN_PATH=${API_TOKEN_PATH:-/var/run/secrets/kubernetes.io/serviceaccount/token}
KUBE_TOKEN=$(< ${API_TOKEN_PATH})
KUBERNETES_PORT_443_TCP_ADDR=${KUBERNETES_PORT_443_TCP_ADDR:-kubernetes}

kubectl -n kube-system get secret cilium-etcd-client-tls > /dev/null 2>&1 || {
	echo "Secret cilium-etcd-client-tls not found. Generating new secrets..."

	echo "generating CA certs ==="
	cfssl gencert -initca certs/ca-csr.json | cfssljson -bare ca

	echo "generating etcd peer certs ==="
	cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=certs/ca-config.json -profile=peer certs/peer.json | cfssljson -bare peer

	echo "generating etcd server certs ==="
	cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=certs/ca-config.json -profile=server certs/server.json | cfssljson -bare server

	echo "generating etcd client certs ==="
	cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=certs/ca-config.json -profile=client certs/etcd-client.json | cfssljson -bare etcd-client

	mv etcd-client.pem etcd-client.crt
	mv etcd-client-key.pem etcd-client.key
	cp ca.pem etcd-client-ca.crt

	mv server.pem server.crt
	mv server-key.pem server.key
	cp ca.pem server-ca.crt

	mv peer.pem peer.crt
	mv peer-key.pem peer.key
	mv ca.pem peer-ca.crt

	rm *.csr ca-key.pem

	echo "Removing old secrets..."

	kubectl -n kube-system get secret cilium-etcd-peer-tls > /dev/null 2>&1 && {
		kubectl -n kube-system delete secret cilium-etcd-peer-tls || true
	}

	kubectl -n kube-system get secret cilium-etcd-server-tls > /dev/null 2>&1 && {
		kubectl -n kube-system delete secret cilium-etcd-server-tls || true
	}

	kubectl -n kube-system get secret cilium-etcd-client-tls > /dev/null 2>&1 && {
		kubectl -n kube-system delete secret cilium-etcd-client-tls || true
	}

	echo "Importing new secrets..."

	kubectl create secret generic -n kube-system cilium-etcd-peer-tls --from-file=peer-ca.crt --from-file=peer.crt --from-file=peer.key
	rm peer-ca.crt peer.crt peer.key

	kubectl create secret generic -n kube-system cilium-etcd-server-tls --from-file=server-ca.crt --from-file=server.crt --from-file=server.key
	rm server-ca.crt server.crt server.key

	kubectl create secret generic -n kube-system cilium-etcd-client-tls --from-file=etcd-client-ca.crt --from-file=etcd-client.crt --from-file=etcd-client.key
	rm etcd-client-ca.crt etcd-client.crt etcd-client.key
}

HAS_ANNOTATION=$(kubectl -n kube-system get secret cilium-etcd-secrets -o json | grep "$ANNOTATION" || true)
if [ -z "$HAS_ANNOTATION" ]; then
	deriveCiliumMasterSecret
fi

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
