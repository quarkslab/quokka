# No Alpine because of capstone ...
FROM docker.io/library/python:3.9

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
        doxygen \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --upgrade pip \
    && pip install --no-cache-dir \
        setuptools \
        twine \
        wheel
