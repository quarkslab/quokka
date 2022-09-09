FROM docker.io/library/debian:stable-slim

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
    ca-certificates \
    ccache \
    cmake \
    g++ \
    gcc \
    git \
    libpython3-dev \
    make \
    ninja-build \
    python3-minimal \
    python3-pip \
    python3-venv \
    python-is-python3 \
    unzip \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*  \
    && useradd -m builder  \
    && mkdir -p /opt/ida

ARG IDA_DIRECTORY=ida77/
ARG IDA_PASSWORD

COPY $IDA_DIRECTORY/ida.run /opt/ida/ida.run
COPY $IDA_DIRECTORY/ida.reg /home/builder/.idapro/ida.reg

RUN chmod +x /opt/ida/ida.run && \
    ( \
      /opt/ida/ida.run --mode unattended --prefix /opt/ida --installpassword $IDA_PASSWORD --python_version 3 || \
      /opt/ida/ida.run --mode unattended --prefix /opt/ida --installpassword $IDA_PASSWORD \
    ) && \
    rm -rf /opt/ida/ida.run /opt/ida/python /opt/ida/plugins/idapython* && \
    chown -R builder: /opt/ida /home/builder/.idapro

WORKDIR /home/builder/quokka
USER builder

ENV PATH /opt/ida:$PATH
ENV TERM xterm