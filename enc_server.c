#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#define BUF_SIZE 150000

int charToInt(char c) { return (c == ' ') ? 26 : c - 'A'; }
char intToChar(int i) { return (i == 26) ? ' ' : 'A' + i; }

void encrypt(char *plaintext, char *key, char *ciphertext) {
    for (int i = 0; i < strlen(plaintext); i++) {
        int pt = charToInt(plaintext[i]);
        int kt = charToInt(key[i]);
        ciphertext[i] = intToChar((pt + kt) % 27);
    }
    ciphertext[strlen(plaintext)] = '\0';
}

int main(int argc, char *argv[]) {
    if (argc < 2) { fprintf(stderr, "Usage: %s port\n", argv[0]); exit(1); }
    int port = atoi(argv[1]);

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serverAddr, clientAddr;
    socklen_t clientSize = sizeof(clientAddr);
    char buffer[BUF_SIZE], key[BUF_SIZE], result[BUF_SIZE];

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    serverAddr.sin_addr.s_addr = INADDR_ANY;

    bind(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
    listen(sockfd, 5);

    while (1) {
        int newsockfd = accept(sockfd, (struct sockaddr *)&clientAddr, &clientSize);
        memset(buffer, 0, BUF_SIZE);
        recv(newsockfd, buffer, BUF_SIZE - 1, 0);
        recv(newsockfd, key, BUF_SIZE - 1, 0);
        encrypt(buffer, key, result);
        send(newsockfd, result, strlen(result), 0);
        close(newsockfd);
    }
    close(sockfd);
    return 0;
}
