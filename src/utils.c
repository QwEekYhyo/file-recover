#include "utils.h"

#include <stdio.h>
#include <sys/stat.h>
#include <inttypes.h>

void print_hex_ascii(const unsigned char* buf, size_t len, uint64_t base_offset) {
    printf("Offset 0x%016" PRIx64 " (%" PRIu64 "):\n", base_offset, base_offset);
    for (size_t i = 0; i < len; i += 16) {
        printf("%08zx  ", i);
        for (size_t j = 0; j < 16; ++j) {
            if (i + j < len) printf("%02X ", buf[i + j]);
            else printf("   ");
        }
        printf(" ");
        for (size_t j = 0; j < 16 && i + j < len; ++j) {
            unsigned char c = buf[i + j];
            putchar((c >= 32 && c <= 126) ? c : '.');
        }
        putchar('\n');
    }
    putchar('\n');
}

uint32_t be32(const unsigned char* b) {
    return ((uint32_t) b[0] << 24) | ((uint32_t) b[1] << 16) | ((uint32_t) b[2] << 8)
           | ((uint32_t) b[3]);
}

int ensure_imgs_dir(void) {
    struct stat st;
    if (stat("imgs", &st) == 0) {
        if (S_ISDIR(st.st_mode)) return 0;
        fprintf(stderr, "'imgs' exists but is not a directory\n");
        return -1;
    }
    if (mkdir("imgs", 0755) != 0) {
        perror("mkdir imgs");
        return -1;
    }
    return 0;
}
