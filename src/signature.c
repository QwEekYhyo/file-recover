#include <signature.h>

#include <stdio.h>

void print_found(struct Signature* sig) {
    switch (sig->type) {
    case PNG:
        printf("Found a PNG signature\n");
        break;
    case JPEG:
        printf("Found a JPEG signature\n");
        break;
    case PDF:
        printf("Found a PDF signature\n");
        break;
    }
}

struct Signature signatures[N_SIGNATURE] = {
    {
        .type          = PNG,
        .buffer        = {0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a},
        .size          = 8,
        .current_index = 0,
        .handle_found  = print_found,
    },
    {
        .type          = JPEG,
        .buffer        = {0xff, 0xd8, 0xff},
        .size          = 3,
        .current_index = 0,
        .handle_found  = print_found,
    },
    {
        .type          = PDF,
        .buffer        = "%PDF",
        .size          = 4,
        .current_index = 0,
        .handle_found  = print_found,
    },
};

void reset_indices(struct Signature* signatures, size_t n) {
    for (size_t i = 0; i < n; i++) {
        signatures[i].current_index = 0;
    }
}
