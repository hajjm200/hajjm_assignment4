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

static ssize_t send_all(int fd,const void*buf,size_t len){
    const char*p=(const char*)buf; size_t s=0;
    while(s<len){ ssize_t n=send(fd,p+s,len-s,0);
        if(n<0){ if(errno==EINTR) continue; return -1; }
        if(n==0) break; s+=(size_t)n; } return (ssize_t)s; }
static ssize_t recv_n(int fd,void*buf,size_t len){
    char*p=(char*)buf; size_t g=0;
    while(g<len){ ssize_t n=recv(fd,p+g,len-g,0);
        if(n<0){ if(errno==EINTR) continue; return -1; }
        if(n==0) break; g+=(size_t)n; } return (ssize_t)g; }
static ssize_t recv_line(int fd,char*buf,size_t cap){
    size_t i=0; while(i+1<cap){ char c; ssize_t n=recv(fd,&c,1,0);
        if(n<0){ if(errno==EINTR) continue; return -1; }
        if(n==0) return -1; if(c=='\n'){ buf[i]='\0'; return (ssize_t)i; }
        buf[i++]=c; } errno=EMSGSIZE; return -1; }

static int valid_char(char c){ return (c==' ')||(c>='A'&&c<='Z'); }
static char* read_file_strip_newline(const char* path,size_t* outLen){
    FILE*f=fopen(path,"rb"); if(!f) return NULL;
    fseek(f,0,SEEK_END); long sz=ftell(f); if(sz<0){ fclose(f); return NULL; }
    rewind(f); char*b=(char*)malloc((size_t)sz+1); if(!b){ fclose(f); return NULL; }
    size_t n=fread(b,1,(size_t)sz,f); fclose(f); b[n]='\0';
    if(n>0&&b[n-1]=='\n'){ b[n-1]='\0'; n--; } *outLen=n; return b;
}
static int validate_allowed(const char*s,size_t n){
    for(size_t i=0;i<n;i++) if(!valid_char(s[i])) return 0; return 1; }

int main(int argc,char*argv[]){
    if(argc!=4){ fprintf(stderr,"Usage: %s <ciphertext_file> <key_file> <port>\n",argv[0]); return 1; }
    const char* cipherPath=argv[1]; const char* keyPath=argv[2]; int port=atoi(argv[3]);

    size_t cipher_len=0,key_len=0;
    char* cipher=read_file_strip_newline(cipherPath,&cipher_len);
    if(!cipher){ fprintf(stderr,"dec_client error: cannot read %s\n",cipherPath); return 1; }
    char* key=read_file_strip_newline(keyPath,&key_len);
    if(!key){ fprintf(stderr,"dec_client error: cannot read %s\n",keyPath); free(cipher); return 1; }

    if(!validate_allowed(cipher,cipher_len)||!validate_allowed(key,key_len)){
        fprintf(stderr,"dec_client error: input contains bad characters\n");
        free(cipher); free(key); return 1;
    }
    if(key_len<cipher_len){
        fprintf(stderr,"Error: key '%s' is too short\n", keyPath);
        free(cipher); free(key); return 1;
    }

    int fd=socket(AF_INET,SOCK_STREAM,0);
    if(fd<0){ fprintf(stderr,"Error: could not contact dec_server on port %d\n",port);
        free(cipher); free(key); return 2; }
    struct sockaddr_in serv={0};
    serv.sin_family=AF_INET; serv.sin_port=htons(port); serv.sin_addr.s_addr=htonl(INADDR_LOOPBACK);
    if(connect(fd,(struct sockaddr*)&serv,sizeof(serv))<0){
        fprintf(stderr,"Error: could not contact dec_server on port %d\n",port);
        close(fd); free(cipher); free(key); return 2;
    }

    if(send_all(fd,"DEC\n",4)<0){ fprintf(stderr,"Error: could not contact dec_server on port %d\n",port);
        close(fd); free(cipher); free(key); return 2; }
    char line[64];
    if(recv_line(fd,line,sizeof(line))<0 || strcmp(line,"OK")!=0){
        fprintf(stderr,"Error: could not contact dec_server on port %d\n",port);
        close(fd); free(cipher); free(key); return 2;
    }

    char hdr[64]; int m=snprintf(hdr,sizeof(hdr),"%zu\n",cipher_len);
    if(m<=0 || send_all(fd,hdr,(size_t)m)<0){ fprintf(stderr,"Error: could not contact dec_server on port %d\n",port);
        close(fd); free(cipher); free(key); return 2; }
    m=snprintf(hdr,sizeof(hdr),"%zu\n",key_len);
    if(m<=0 || send_all(fd,hdr,(size_t)m)<0){ fprintf(stderr,"Error: could not contact dec_server on port %d\n",port);
        close(fd); free(cipher); free(key); return 2; }

    if(send_all(fd,cipher,cipher_len)<0 || send_all(fd,key,key_len)<0){
        fprintf(stderr,"Error: could not contact dec_server on port %d\n",port);
        close(fd); free(cipher); free(key); return 2;
    }

    char* plain=(char*)malloc(cipher_len+1); if(!plain){
        fprintf(stderr,"dec_client error: out of memory\n"); close(fd); free(cipher); free(key); return 1; }
    if(recv_n(fd,plain,cipher_len)!=(ssize_t)cipher_len){
        fprintf(stderr,"Error: could not contact dec_server on port %d\n",port);
        close(fd); free(cipher); free(key); free(plain); return 2;
    }
    char nl; (void)recv_n(fd,&nl,1);
    plain[cipher_len]='\0'; printf("%s\n",plain);

    free(cipher); free(key); free(plain); close(fd); return 0;
}
