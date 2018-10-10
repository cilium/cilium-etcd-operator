ifndef VERSION
VERSION=latest
endif

all:
	docker build -t cilium/cilium-etcd-operator:${VERSION} .
	@echo "\nTo push to the registry:\ndocker push cilium/cilium-etcd-operator:${VERSION}"
