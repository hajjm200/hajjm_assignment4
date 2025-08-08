// === keygen.c ===
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static char pick(void){
    int r = rand() % 27;           // 0..26
    return r == 26 ? ' ' : ('A' + r);
}

int main(int argc, char *argv[]){
    if (argc != 2) {
        fprintf(stderr, "Usage: %s keylength\n", argv[0]);
        return 1;
    }
    int n = atoi(argv[1]);
    if (n <= 0) {
        fprintf(stderr, "keygen error: length must be positive\n");
        return 1;
    }
    srand((unsigned int)time(NULL));
    for (int i = 0; i < n; i++) putchar(pick());
    putchar('\n');
    return 0;
}
