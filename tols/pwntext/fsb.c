#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
void init(){
    setbuf(stdin,0);
    setbuf(stdout,0);
    setbuf(stderr,0);
    return;
}
void fsb(char* format,int n){
    puts("please input your name:");
    read(0,format,n);
    printf("hello");
    printf(format);
    return;
}
void vuln(){
    char *   format= malloc(200);
    for(int i=0;i<30;i++){
        fsb(format,200);
    }
    free(format);
    return;
}
void main(){
    init();
    vuln();
    return;
}