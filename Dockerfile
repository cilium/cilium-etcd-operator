FROM cilium/kubectl:1.0
WORKDIR /
ADD . /
ENTRYPOINT ["sh", "/run.sh"]
