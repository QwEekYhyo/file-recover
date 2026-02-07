#ifndef FILE_RECOVER_SIGNATURE_H
#define FILE_RECOVER_SIGNATURE_H

#include <stddef.h>

#define MAX_SIGNATURE_LEN 8
#define N_SIGNATURE       3

enum FileType {
    PNG,
    JPEG,
    PDF,
};

struct Signature {
    enum FileType type;
    unsigned char buffer[MAX_SIGNATURE_LEN];
    size_t size;
    size_t current_index;
    void (*handle_found)(struct Signature* sig);
};

void reset_indices(struct Signature* signatures, size_t n);

#endif
