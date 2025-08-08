#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static int charToInt(char c) { return (c == ' ') ? 26 : (c - 'A'); }
static char intToChar(int x) { return (x == 26) ? ' ' : ('A' + x); }

static void encrypt_buf(const char *plain, const char *key, char *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        int pt = charToInt(plain[i]);
        int kt = charToInt(key[i]);
        out[i] = intToChar((pt + kt) % 27);
    }
    out[n] = '\0';
}

static ssize_t send_all(int fd, const void *buf, size_t len) {
    const char *p = (const char *)buf;
    size_t sent = 0;
    while (sent < len) {
        ssize_t n = send(fd, p + sent, len - sent, 0);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        if (n == 0) break;
        sent += (size_t)n;
    }
    return (ssize_t)sent;
}
static ssize_t recv_n(int fd, void *buf, size_t len) {
    char *p = (char *)buf; size_t got = 0;
    while (got < len) {
        ssize_t n = recv(fd, p + got, len - got, 0);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        if (n == 0) break;
        got += (size_t)n;
    }
    return (ssize_t)got;
}
static ssize_t recv_line(int fd, char *buf, size_t cap) {
    size_t i = 0;
    while (i + 1 < cap) {
        char c; ssize_t n = recv(fd, &c, 1, 0);
        if (n < 0) { if (errno == EINTR) continue; return -1; }
        if (n == 0) return -1;
        if (c == '\n') { buf[i] = '\0'; return (ssize_t)i; }
        buf[i++] = c;
    }
    errno = EMSGSIZE; return -1;
}

static void sigchld_handler(int sig){(void)sig;int e=errno;while(waitpid(-1,NULL,WNOHANG)>0){} errno=e;}

static void handle_client(int connfd) {
    char line[64];
    if (recv_line(connfd, line, sizeof(line)) < 0) goto bye;
    if (strcmp(line, "ENC") != 0) { (void)send_all(connfd,"REJECT\n",7); goto bye; }
    if (send_all(connfd, "OK\n", 3) < 0) goto bye;

    if (recv_line(connfd, line, sizeof(line)) < 0) goto bye;
    long plain_len = strtol(line, NULL, 10); if (plain_len <= 0) goto bye;
    if (recv_line(connfd, line, sizeof(line)) < 0) goto bye;
    long key_len = strtol(line, NULL, 10); if (key_len < plain_len) goto bye;

    char *plain = (char*)malloc((size_t)plain_len);
    char *key   = (char*)malloc((size_t)key_len);
    char *cipher= (char*)malloc((size_t)plain_len + 1);
    if(!plain||!key||!cipher) goto bye2;

    if (recv_n(connfd, plain,  (size_t)plain_len)  != plain_len)  goto bye2;
    if (recv_n(connfd, key,    (size_t)key_len)    != key_len)    goto bye2;

    encrypt_buf(plain, key, cipher, (size_t)plain_len);
    if (send_all(connfd, cipher, (size_t)plain_len) < 0) goto bye2;
    (void)send_all(connfd, "\n", 1);

bye2:
    free(plain); free(key); free(cipher);
bye:
    close(connfd);
    _exit(0);
}

int main(int argc, char *argv[]) {
    if (argc != 2) { fprintf(stderr,"Usage: %s listening_port\n", argv[0]); return 1; }
    int port = atoi(argv[1]);

    struct sigaction sa={0}; sa.sa_handler=sigchld_handler; sa.sa_flags=SA_RESTART;
    sigaction(SIGCHLD,&sa,NULL);

    int listenFD = socket(AF_INET, SOCK_STREAM, 0);
    if (listenFD < 0) { perror("socket"); return 1; }
    int yes=1; setsockopt(listenFD,SOL_SOCKET,SO_REUSEADDR,&yes,sizeof(yes));

    struct sockaddr_in addr={0};
    addr.sin_family=AF_INET; addr.sin_port=htons(port); addr.sin_addr.s_addr=htonl(INADDR_ANY);
    if (bind(listenFD,(struct sockaddr*)&addr,sizeof(addr))<0){ perror("bind"); return 1; }
    if (listen(listenFD,5)<0){ perror("listen"); return 1; }

    for(;;){
        struct sockaddr_in cli; socklen_t cl=sizeof(cli);
        int connfd = accept(listenFD,(struct sockaddr*)&cli,&cl);
        if (connfd<0){ if(errno==EINTR) continue; perror("accept"); continue; }
        pid_t pid=fork();
        if (pid<0){ perror("fork"); close(connfd); continue; }
        if (pid==0){ close(listenFD); handle_client(connfd); }
        else { close(connfd); }
    }
}
