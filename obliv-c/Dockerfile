FROM ubuntu:20.04
WORKDIR /root
RUN apt-get update && apt-get install -y \
  ocaml \
  libgcrypt20-dev \
  libgmp-dev \
  ocaml-findlib \
  opam \
  m4 \
  git \
  vim \
  gcc \
  make
RUN git clone https://github.com/samee/obliv-c
#如果访问github速度慢，可以使用这个加速地址：
#RUN git clone https://github.com.cnpmjs.org/samee/obliv-c
WORKDIR /root/obliv-c
RUN opam init -a --disable-sandboxing && \
  opam switch create 4.06.0 && \
  opam switch 4.06.0 && \
  eval `opam config env` && \
  opam install -y camlp4 ocamlfind batteries bignum ocamlbuild && \
  ./configure && make
#可以将宿主机中的代码mount到容器的projects目录，使用容器进行编译和运行
VOLUME ["/root/projects"]
WORKDIR /root/projects
#为了后续测试方便特此安装了一些网络工具
RUN apt-get update && \
    apt-get install -y iputils-ping && \
    apt-get install -y telnet && \
    apt-get install -y net-tools && \
    apt-get install -y tcpdump