FROM registry.access.redhat.com/ubi9/ubi-minimal:latest

ENV LC_ALL=C.utf8
ENV LANG=C.utf8
ENV HOME=/opt/app-root/src
WORKDIR $HOME

USER root
ADD https://copr.fedorainfracloud.org/coprs/g/insights/postgresql-16/repo/epel-9/group_insights-postgresql-16-epel-9.repo group_insights-postgresql-16-epel-9.repo
# Install & upgrade RHEL packages
RUN (microdnf module enable -y postgresql:16 || \
     cp group_insights-postgresql-16-epel-9.repo /etc/yum.repos.d/postgresql.repo \
    ) && \
    microdnf -y --setopt=install_weak_deps=0 --setopt=tsflags=nodocs install \
      python3.12 postgresql git-core && \
    microdnf -y upgrade && \
    microdnf clean all && \
    rm -rf /mnt/rootfs/var/cache/* /mnt/rootfs/var/log/dnf* /mnt/rootfs/var/log/yum.*

# alias pip and python for compatibility
RUN alternatives --install /usr/bin/pip3 pip3 /usr/bin/pip3.12 1 && \
    alternatives --install /usr/bin/pip pip /usr/bin/pip3 1 && \
    alternatives --install /usr/bin/python3 python3 /usr/bin/python3.12 1 && \
    alternatives --install /usr/bin/python python /usr/bin/python3 1

# Needed because $HOME isn't owned by user 1001
RUN chown 1001 $HOME && install -o 1001 -d $HOME/.cache

# API, service and content import all need pip and pipenv installed
COPY Pipfile Pipfile.lock ./
# Install build tools for psycopg2, then remove them and dependencies after
# in one step so the FS layer has minimal changes
RUN microdnf -y install python3.12-pip python3.12-devel gcc libpq-devel && \
    pip3 -q install pipenv && \
    pipenv install && \
    microdnf remove -y python3.12-devel gcc libpq-devel \
      acl binutils binutils-gold cpp \
      elfutils-debuginfod-client elfutils-default-yama-scope elfutils-libelf \
      elfutils-libs libxcrypt-devel glibc-devel make libgomp libmpc \
      libpkgconf pkgconf pkgconf-pkg-config \
      glibc-headers kernel-headers && \
# The unit tests need to install --dev packages, which needs to write to
# .local, so we need to set the permissions so 1001 can do that here
    chown -R 1001 .cache .local

# Set Django 5.2+ minimum PostgreSQL version to 13
RUN sed -i s/\(14,\)/\(13,\)/g $(pipenv --venv)/lib/python3.12/site-packages/django/db/backends/postgresql/features.py

# Needed for Prometheus
RUN install -o 1001 -d /metrics

# Now transition to the container user
USER 1001
COPY ./api ./api
COPY ./service ./service

COPY container_init.sh container_init.sh

EXPOSE 8000
