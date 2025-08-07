#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define BUF_SIZE 150000

void readFile(const char *filename, char *buffer) {
    FILE *fp = fopen(filename, "r");
    if (!fp) { perror("fopen"); exit(1); }
    fgets(buffer, BUF_SIZE, fp);
    buffer[strcspn(buffer, "\n")] = '\0';
    fclose(fp);
}

int main(int argc, char *argv[]) {
    if (argc < 4) { fprintf(stderr, "Usage: %s plaintext key port\n", argv[0]); exit(1); }
    char plaintext[BUF_SIZE], key[BUF_SIZE], buffer[BUF_SIZE];

    readFile(argv[1], plaintext);
    readFile(argv[2], key);
    if (strlen(key) < strlen(plaintext)) { fprintf(stderr, "Error: key too short\n"); exit(1); }

    int port = atoi(argv[3]);
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in serverAddr;
    struct hostent *server = gethostbyname("localhost");

    memset(&serverAddr, 0, sizeof(serverAddr));
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    memcpy(&serverAddr.sin_addr.s_addr, server->h_addr, server->h_length);

    connect(sockfd, (struct sockaddr *)&serverAddr, sizeof(serverAddr));
    send(sockfd, plaintext, strlen(plaintext), 0);
    send(sockfd, key, strlen(key), 0);

    memset(buffer, 0, BUF_SIZE);
    recv(sockfd, buffer, BUF_SIZE - 1, 0);
    printf("%s\n", buffer);

    close(sockfd);
    return 0;
}
