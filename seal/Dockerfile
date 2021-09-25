FROM ubuntu:20.04
WORKDIR /root
ENV DEBIAN_FRONTEND noninteractive
RUN apt-get update && apt-get install -y git cmake clang-7 build-essential && \
	rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/microsoft/SEAL.git
WORKDIR /root/SEAL
RUN cmake -S . -B build && cmake --build build && cmake --install build
#可以将宿主机中的代码mount到容器的projects目录，使用容器进行编译和运行
VOLUME ["/root/projects"]
WORKDIR /root/projects