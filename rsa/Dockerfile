FROM ubuntu:20.04

RUN apt-get update && \
    apt-get install -y \
    python3-pip python3-gmpy2

RUN pip3 install pycryptodome

VOLUME ["/root/projects"]
WORKDIR /root/projects