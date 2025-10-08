#ifndef FILE_RECOVER_UTILS_H
#define FILE_RECOVER_UTILS_H

#include <stdint.h>
#include <stdlib.h>

void print_hex_ascii(const unsigned char* buf, size_t len, uint64_t base_offset);

uint32_t be32(const unsigned char* b);

int ensure_imgs_dir(void);

#endif
