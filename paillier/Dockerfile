FROM ubuntu:20.04

RUN apt-get update && \
	apt-get install -y \
	python3-pip

RUN pip3 install phe

VOLUME ["/root/projects"]
WORKDIR /root/projects