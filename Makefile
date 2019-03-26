include Makefile.defs
ifndef VERSION
VERSION=latest
endif

all:
	docker build -t cilium/cilium-etcd-operator:${VERSION} .
	@echo "\nTo push to the registry:\ndocker push cilium/cilium-etcd-operator:${VERSION}"

cilium-etcd-operator:
	CGO_ENABLED=0 GOOS=linux go build $(GOBUILD) -a -installsuffix cgo -o $@
