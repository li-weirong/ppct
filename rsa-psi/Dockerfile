FROM ubuntu:20.04

RUN apt-get update && \
    apt-get install -y \
    python3-pip python3-gmpy2

RUN pip3 install bitarray==1.7.1 && \
    pip3 install pycryptodome && \
    pip3 install pybloom_live

VOLUME ["/root/projects"]
WORKDIR /root/projects