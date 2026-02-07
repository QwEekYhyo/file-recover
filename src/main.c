#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdlib.h>

#include <signature.h>

#define CHUNK_SIZE    16384
#define OVERLAP       (MAX_SIGNATURE_LEN - 1)

extern struct Signature signatures[];

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <device>\n", argv[0]);
        return 1;
    }

    FILE* block_device = fopen(argv[1], "rb");
    if (!block_device) {
        perror("fopen() failed on block device");
        return 1;
    }

    unsigned char* window_buffer = malloc(CHUNK_SIZE * sizeof(char));
    if (!window_buffer) {
        perror("malloc() for window reading buffer failed");
        fclose(block_device);
        return 1;
    }

    for (;;) {
        unsigned long bytes_read = fread(window_buffer, sizeof(window_buffer[0]), CHUNK_SIZE, block_device);

        if (!bytes_read) {
            break;
        }

        for (size_t i = 0; i < bytes_read; i++) {
            for (size_t sig_index = 0; sig_index < N_SIGNATURE; sig_index++) {
                struct Signature* sig = &signatures[sig_index];

                if (window_buffer[i] == sig->buffer[sig->current_index]) {
                    sig->current_index++;

                    if (sig->current_index == sig->size) {
                        reset_indices(signatures, N_SIGNATURE);
                        sig->handle_found(sig);
                    }
                } else {
                    sig->current_index = 0;
                }
            }
        }
        
        if (bytes_read < CHUNK_SIZE) {
            break;
        }

        // I am using a window overlap to avoid missing signatures that
        // are separeted between two windows,
        // problem is: the magic words don't all have the same length
        // so shorter magic words like JPEG's could be found twice
        // but this shouldn't be a problem when we are going to seek past the file
        int error = fseeko(block_device, bytes_read - OVERLAP, SEEK_CUR);
        if (error) {
            perror("fseeko() before reading next window failed");
            free(window_buffer);
            fclose(block_device);
            return 1;
        }
    }

    free(window_buffer);
    fclose(block_device);
    return 0;
}
