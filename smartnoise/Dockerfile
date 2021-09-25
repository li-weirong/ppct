FROM ubuntu:20.04
RUN apt-get update && \
    apt-get install -y \
    python3-pip
#使用国内镜像加速python包的安装
RUN pip3 install opendp-smartnoise numpy pandas scipy matplotlib \
    -i http://mirrors.aliyun.com/pypi/simple/ --trusted-host mirrors.aliyun.com
#可以将宿主机中的代码mount到容器的projects目录，使用容器进行来运行
VOLUME ["/root/projects"]
WORKDIR /root/projects