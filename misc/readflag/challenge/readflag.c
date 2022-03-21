#include <stdio.h>

const char flag[] = "zer0pts{Dear diary... Wait, are your reading this? Stop!}";

int main() {
    FILE *random;
    if ((random = fopen("/dev/urandom", "rb")) == NULL) {
        perror("fopen");
        return 1;
    }

    for (const unsigned char *f = flag; *f; f++) {
        unsigned char r;
        if (fread(&r, 1, 1, random) != 1) {
            perror("fread");
            return 1;
        }
        printf("%02x", *f ^ r);
    }

    printf("\n");

    return 0;
}
