FROM laslabs/alpine-cfssl as cfssl
WORKDIR /

FROM cilium/kubectl:1.0
COPY --from=cfssl /usr/bin/cfssl /usr/bin/cfssljson /usr/bin/
WORKDIR /
ADD . /
ENTRYPOINT ["sh", "/run.sh"]
