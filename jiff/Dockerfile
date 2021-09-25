FROM node:12
WORKDIR /root

#如果访问github速度慢，可以使用这个地址加速：
RUN git clone https://github.com.cnpmjs.org/multiparty/jiff
#RUN git clone https://github.com/multiparty/jiff
WORKDIR /root/jiff
RUN npm install
#可以将宿主机中的代码mount到容器的projects目录，使用容器进行编译和运行
VOLUME ["/root/jiff/projects"]
WORKDIR /root/jiff/projects
#为了后续测试方便特此安装了一些网络工具
RUN apt-get update && \
    apt-get install -y iputils-ping && \
    apt-get install -y telnet && \
    apt-get install -y net-tools && \
    apt-get install -y tcpdump