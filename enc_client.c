// === enc_client.c ===
#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static ssize_t send_all(int fd, const void *buf, size_t len){
    const char *p=(const char*)buf; size_t sent=0;
    while(sent<len){ ssize_t n=send(fd,p+sent,len-sent,0);
        if(n<0){ if(errno==EINTR) continue; return -1; }
        if(n==0) break; sent+=(size_t)n; } return (ssize_t)sent; }
static ssize_t recv_n(int fd, void *buf, size_t len){
    char *p=(char*)buf; size_t got=0;
    while(got<len){ ssize_t n=recv(fd,p+got,len-got,0);
        if(n<0){ if(errno==EINTR) continue; return -1; }
        if(n==0) break; got+=(size_t)n; } return (ssize_t)got; }
static ssize_t recv_line(int fd, char *buf, size_t cap){
    size_t i=0; while(i+1<cap){ char c; ssize_t n=recv(fd,&c,1,0);
        if(n<0){ if(errno==EINTR) continue; return -1; }
        if(n==0) return -1; if(c=='\n'){ buf[i]='\0'; return (ssize_t)i; }
        buf[i++]=c; } errno=EMSGSIZE; return -1; }

static int valid_char(char c){ return (c==' ') || (c>='A'&&c<='Z'); }
static char* read_file_strip_newline(const char* path,size_t* outLen){
    FILE* f=fopen(path,"rb"); if(!f) return NULL;
    fseek(f,0,SEEK_END); long sz=ftell(f); if(sz<0){ fclose(f); return NULL; }
    rewind(f); char* b=(char*)malloc((size_t)sz+1); if(!b){ fclose(f); return NULL; }
    size_t n=fread(b,1,(size_t)sz,f); fclose(f); b[n]='\0';
    if(n>0 && b[n-1]=='\n'){ b[n-1]='\0'; n--; } *outLen=n; return b;
}
static int validate_allowed(const char* s,size_t n){
    for(size_t i=0;i<n;i++) if(!valid_char(s[i])) return 0; return 1; }

int main(int argc,char*argv[]){
    if(argc!=4){ fprintf(stderr,"Usage: %s <plaintext_file> <key_file> <port>\n",argv[0]); return 1; }
    const char* plainPath=argv[1]; const char* keyPath=argv[2]; int port=atoi(argv[3]);

    size_t plain_len=0,key_len=0;
    char* plain=read_file_strip_newline(plainPath,&plain_len);
    if(!plain){ fprintf(stderr,"enc_client error: cannot read %s\n",plainPath); return 1; }
    char* key=read_file_strip_newline(keyPath,&key_len);
    if(!key){ fprintf(stderr,"enc_client error: cannot read %s\n",keyPath); free(plain); return 1; }

    if(!validate_allowed(plain,plain_len)||!validate_allowed(key,key_len)){
        fprintf(stderr,"enc_client error: input contains bad characters\n");
        free(plain); free(key); return 1;
    }
    if(key_len<plain_len){
        fprintf(stderr,"Error: key '%s' is too short\n", keyPath);
        free(plain); free(key); return 1;
    }

    int fd=socket(AF_INET,SOCK_STREAM,0);
    if(fd<0){ fprintf(stderr,"Error: could not contact enc_server on port %d\n",port);
        free(plain); free(key); return 2; }
    struct sockaddr_in serv={0};
    serv.sin_family=AF_INET; serv.sin_port=htons(port);
    serv.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(connect(fd,(struct sockaddr*)&serv,sizeof(serv))<0){
        fprintf(stderr,"Error: could not contact enc_server on port %d\n",port);
        close(fd); free(plain); free(key); return 2;
    }

    if(send_all(fd,"ENC\n",4)<0){ fprintf(stderr,"Error: could not contact enc_server on port %d\n",port);
        close(fd); free(plain); free(key); return 2; }
    char line[64];
    if(recv_line(fd,line,sizeof(line))<0 || strcmp(line,"OK")!=0){
        fprintf(stderr,"Error: could not contact enc_server on port %d\n",port);
        close(fd); free(plain); free(key); return 2;
    }

    char hdr[64]; int m=snprintf(hdr,sizeof(hdr),"%zu\n",plain_len);
    if(m<=0 || send_all(fd,hdr,(size_t)m)<0){ fprintf(stderr,"Error: could not contact enc_server on port %d\n",port);
        close(fd); free(plain); free(key); return 2; }
    m=snprintf(hdr,sizeof(hdr),"%zu\n",key_len);
    if(m<=0 || send_all(fd,hdr,(size_t)m)<0){ fprintf(stderr,"Error: could not contact enc_server on port %d\n",port);
        close(fd); free(plain); free(key); return 2; }

    if(send_all(fd,plain,plain_len)<0 || send_all(fd,key,key_len)<0){
        fprintf(stderr,"Error: could not contact enc_server on port %d\n",port);
        close(fd); free(plain); free(key); return 2;
    }

    char* cipher=(char*)malloc(plain_len+1); if(!cipher){
        fprintf(stderr,"enc_client error: out of memory\n"); close(fd); free(plain); free(key); return 1; }
    if(recv_n(fd,cipher,plain_len)!=(ssize_t)plain_len){
        fprintf(stderr,"Error: could not contact enc_server on port %d\n",port);
        close(fd); free(plain); free(key); free(cipher); return 2;
    }
    char nl; (void)recv_n(fd,&nl,1);
    cipher[plain_len]='\0'; printf("%s\n",cipher);

    free(plain); free(key); free(cipher); close(fd); return 0;
}
