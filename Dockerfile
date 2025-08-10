FROM quay.io/fedora/fedora as base

RUN dnf -y install --setopt=tsflags=nodocs --setopt=install_weak_deps=0 --nodocs\
      python3.13-devel autoconf automake bzip2 gcc-c++ gd-devel gdb git libcurl-devel \
      libpq-devel libxml2-devel libxslt-devel lsof make mariadb-connector-c-devel \
      openssl-devel patch procps-ng npm redhat-rpm-config sqlite-devel unzip wget which zlib-devel \
      python3.13-pip ; \
      yum -y clean all --enablerepo='*'

FROM base as builder
COPY requirements.txt /tmp/requirements.txt
RUN dnf -y --setopt=install_weak_deps=0 --nodocs --use-host-config \
      --installroot /output \
      install \
      glibc glibc-minimal-langpack libstdc++ \
      bash \
      python3.13 python3.13-requests python3.13-dateutil python3.13-packaging libpq ; \
      yum -y clean all --enablerepo='*'

RUN pip3.13 install --prefix=/usr --root /output -r /tmp/requirements.txt

FROM scratch 

COPY --from=builder /output / 
#COPY --from=base /root/buildinfo /root/buildinfo
COPY proxy.py /opt/app/proxy.py
COPY prompolicy /opt/app/prompolicy

USER 1001
WORKDIR /opt/app
ENV PROMETHEUS_MULTIPROC_DIR=/tmp
ENV PYTHON_PATH=/opt/app
ENTRYPOINT [ "/usr/bin/gunicorn" ]
CMD [ "--pythonpath", "/usr/bin/python3.13", "--bind", "0.0.0.0:8080", "proxy:app_factory", "--worker-class", "aiohttp.GunicornWebWorker", "--access-logfile", "-"]
