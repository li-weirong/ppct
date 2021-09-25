typedef struct protocolIO {
  // -1：Alice小于Bob, 0：Alice等于Bob，1：Alice大于Bob
  int cmp; //隐私计算输出
  int mywealth;	//隐私计算输入
} protocolIO;

void millionaire(void* args);