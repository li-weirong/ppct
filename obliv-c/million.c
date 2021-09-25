#include<stdio.h>
#include<obliv.h>
#include"million.h"

int main(int argc,char *argv[]) {
  ProtocolDesc pd;
  protocolIO io;
  const char* remote_host = (strcmp(argv[2], "--")==0?NULL:argv[2]);
  if(!remote_host){
    if(protocolAcceptTcp2P(&pd, argv[1])){  //Alice等待Bob连接
      fprintf(stderr, "TCP accept failed\n");
      exit(1);
    }
  }
  else{
    if(protocolConnectTcp2P(&pd,remote_host,argv[1])!=0){ //Bob主动连接Alice
      fprintf(stderr,"TCP connect failed\n");
      exit(1);
    }
  }
  setCurrentParty(&pd, remote_host?2:1); //设置参与方编号，Alice是1，Bob是2
  sscanf(argv[3],"%d",&io.mywealth);  //这里省略输入合法性检验
  execYaoProtocol(&pd,millionaire,&io); //执行百万富翁比较
  cleanupProtocol(&pd);
  fprintf(stderr,"Result: %d\n",io.cmp);
  return 0;
}