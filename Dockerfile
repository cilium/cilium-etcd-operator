FROM docker.io/library/golang:1.12.1 as builder
LABEL maintainer="maintainer@cilium.io"
ADD . /go/src/github.com/cilium/cilium-etcd-operator
WORKDIR /go/src/github.com/cilium/cilium-etcd-operator
RUN make cilium-etcd-operator
RUN strip cilium-etcd-operator

FROM scratch
LABEL maintainer="maintainer@cilium.io"
COPY --from=builder /go/src/github.com/cilium/cilium-etcd-operator/cilium-etcd-operator /usr/bin/cilium-etcd-operator
WORKDIR /
CMD ["/usr/bin/cilium-etcd-operator"]
