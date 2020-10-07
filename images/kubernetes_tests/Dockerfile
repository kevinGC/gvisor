FROM gcr.io/k8s-testimages/kubekins-e2e:v20200819-491a5ae-master

COPY ["entrypoint.sh", "/usr/local/bin/"]

RUN ["chmod", "a+x", "/usr/local/bin/entrypoint.sh"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
