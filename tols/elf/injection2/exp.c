#include <stdio.h>
#include <sys/ptrace.h>
//cat /proc/131/maps
int main(int argv , char **argc){
 
  int data ;
  int stat ;
  int pid = atoi(argc[1]) ;//这里需要手动传入命令行参数 target的pid
  ptrace(PTRACE_ATTACH, pid, NULL, NULL) ;
  wait(&stat) ;    // 如果不wait，马上进行下一个ptrace的PEEK操作会造成 no such process 错误
  long long int addr = 0 ;
  scanf("%llx",&addr);
  for (; addr < 0x7ffffffff000; ++addr)
  {
    data = ptrace(PTRACE_PEEKDATA, pid, addr, NULL);    // 一次读一个字节
    if(data==0x65636165)
    {
      printf("data = %x , addr = %llx\n" , data , addr) ;
      long long int addr1=addr-1;
      char data1;
      for(int i=0;i<100;i++)
      {
        addr1+=1;
        data1 = ptrace(PTRACE_PEEKDATA, pid, addr1, NULL);
        //write(1,data1,0x10);
        printf("%c" , data1) ;
      }
    }
  }
  ptrace(PTRACE_DETACH, pid, NULL, NULL);
  return 1 ;
}
