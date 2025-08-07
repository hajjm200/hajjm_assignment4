#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define CHAR_POOL "ABCDEFGHIJKLMNOPQRSTUVWXYZ "

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s key_length\n", argv[0]);
        exit(1);
    }

    int length = atoi(argv[1]);
    if (length <= 0) {
        fprintf(stderr, "Error: key length must be a positive integer\n");
        exit(1);
    }

    srand(time(NULL));
    const char *chars = CHAR_POOL;
    for (int i = 0; i < length; i++) {
        int index = rand() % 27;
        printf("%c", chars[index]);
    }
    printf("\n");
    return 0;
}
