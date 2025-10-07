#define _FILE_OFFSET_BITS 64
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define CHUNK_SIZE    (4096 * 4)   // read size per iteration for scanning
#define SIGN_LEN      8            // PNG signature length
#define FOLLOW_BYTES  32           // bytes to print after the signature (hex+ASCII)
#define OVERLAP       (SIGN_LEN - 1)
#define MAX_PNG_BYTES (200 * 1024 * 1024) // 200MB safety cap when extracting PNGs

#define PATH_MAX      20

static const unsigned char png_sig[SIGN_LEN] = {
    0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A
};

static void print_hex_ascii(const unsigned char *buf, size_t len, uint64_t base_offset) {
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

static uint32_t be32(const unsigned char *b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | ((uint32_t)b[3]);
}

static int ensure_imgs_dir(void) {
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

// Extract a PNG starting at match_offset, write to ./imgs/img_{index}.png
// Returns 0 on success, non-zero on failure.
static int extract_png(FILE *fp, uint64_t match_offset, size_t index) {
    char outpath[PATH_MAX];
    snprintf(outpath, sizeof(outpath), "imgs/img_%zu.png", index);

    // Seek to the start of PNG signature
    if (fseeko(fp, (off_t)match_offset, SEEK_SET) != 0) {
        fprintf(stderr, "fseeko to %" PRIu64 " failed: %s\n", match_offset, strerror(errno));
        return -1;
    }

    FILE *out = fopen(outpath, "wb");
    if (!out) {
        fprintf(stderr, "fopen(%s) failed: %s\n", outpath, strerror(errno));
        return -1;
    }

    unsigned char header[SIGN_LEN];
    size_t got = fread(header, 1, SIGN_LEN, fp);
    if (got != SIGN_LEN) {
        fprintf(stderr, "Failed to read PNG signature from source (got %zu bytes)\n", got);
        fclose(out);
        return -1;
    }
    // write signature
    if (fwrite(header, 1, SIGN_LEN, out) != SIGN_LEN) {
        perror("fwrite signature");
        fclose(out);
        return -1;
    }

    uint64_t bytes_copied = SIGN_LEN;

    // Now iterate PNG chunks until we hit IEND (chunks: length(4) + type(4) + data(length) + crc(4))
    while (1) {
        unsigned char len_type[8];
        // read 8 bytes: length (4) + type (4)
        size_t r = fread(len_type, 1, 8, fp);
        if (r != 8) {
            fprintf(stderr, "Unexpected EOF or read error when reading chunk len/type (got %zu bytes)\n", r);
            fclose(out);
            return -1;
        }
        if (fwrite(len_type, 1, 8, out) != 8) {
            perror("fwrite len_type");
            fclose(out);
            return -1;
        }
        bytes_copied += 8;

        uint32_t data_len = be32(len_type);
        char chunk_type[5] = {0};
        memcpy(chunk_type, &len_type[4], 4);

        // safety check on data_len
        if (data_len > MAX_PNG_BYTES || (bytes_copied + data_len + 4) > MAX_PNG_BYTES) {
            fprintf(stderr, "Chunk too large or would exceed MAX_PNG_BYTES (%u bytes) — aborting extraction\n", data_len);
            fclose(out);
            return -1;
        }

        // copy 'data_len' bytes
        size_t to_copy = data_len;
        unsigned char *buf = malloc(CHUNK_SIZE);
        if (!buf) {
            fprintf(stderr, "malloc failed\n");
            fclose(out);
            return -1;
        }

        while (to_copy > 0) {
            size_t step = (to_copy > CHUNK_SIZE) ? CHUNK_SIZE : to_copy;
            size_t rr = fread(buf, 1, step, fp);
            if (rr != step) {
                fprintf(stderr, "Unexpected EOF/err while reading chunk data (want %zu got %zu)\n", step, rr);
                free(buf);
                fclose(out);
                return -1;
            }
            if (fwrite(buf, 1, rr, out) != rr) {
                perror("fwrite chunk data");
                free(buf);
                fclose(out);
                return -1;
            }
            bytes_copied += rr;
            to_copy -= rr;
        }
        free(buf);

        // read and write CRC (4 bytes)
        unsigned char crc[4];
        size_t rc = fread(crc, 1, 4, fp);
        if (rc != 4) {
            fprintf(stderr, "Unexpected EOF/err while reading CRC (got %zu)\n", rc);
            fclose(out);
            return -1;
        }
        if (fwrite(crc, 1, 4, out) != 4) {
            perror("fwrite crc");
            fclose(out);
            return -1;
        }
        bytes_copied += 4;

        // If this was IEND, we are done
        if (memcmp(chunk_type, "IEND", 4) == 0) {
            printf("Extracted PNG to %s (%" PRIu64 " bytes)\n", outpath, bytes_copied);
            fclose(out);
            return 0;
        }

        // Continue to next chunk
    }

    // unreachable
    // return 0;
}

int main(int argc, char **argv) {
    if (argc < 3 || argc > 4) {
        fprintf(stderr, "Usage: %s <file-or-device> <max_matches> [start_offset]\n", argv[0]);
        return 1;
    }

    const char *path = argv[1];
    long max_matches = strtol(argv[2], NULL, 10);
    if (max_matches <= 0) {
        fprintf(stderr, "max_matches must be > 0\n");
        return 1;
    }

    uint64_t start_offset = 0;
    if (argc == 4) {
        start_offset = strtoull(argv[3], NULL, 0);
    }

    if (ensure_imgs_dir() != 0) return 2;

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        fprintf(stderr, "fopen(%s) failed: %s\n", path, strerror(errno));
        return 3;
    }

    if (start_offset != 0ULL) {
        if (fseeko(fp, (off_t)start_offset, SEEK_SET) != 0) {
            fprintf(stderr, "fseeko to start_offset (%" PRIu64 ") failed: %s\n", (uint64_t)start_offset, strerror(errno));
            fclose(fp);
            return 4;
        }
    }

    unsigned char *buf = malloc(CHUNK_SIZE + OVERLAP);
    if (!buf) {
        fprintf(stderr, "malloc failed\n");
        fclose(fp);
        return 5;
    }

    uint64_t file_offset = start_offset;     // offset of the start of current buffer in the file
    size_t read_bytes;
    size_t matches = 0;

    // Initial read
    read_bytes = fread(buf, 1, CHUNK_SIZE, fp);

    while (read_bytes > 0 && matches < (size_t)max_matches) {
        size_t search_limit = (read_bytes >= SIGN_LEN) ? (read_bytes - SIGN_LEN + 1) : 0;
        for (size_t i = 0; i < search_limit && matches < (size_t)max_matches; ++i) {
            if (memcmp(buf + i, png_sig, SIGN_LEN) == 0) {
                uint64_t match_offset = file_offset + i;
                printf("PNG signature found at offset %" PRIu64 " (0x%016" PRIx64 ")\n", match_offset, match_offset);

                // Print signature + following FOLLOW_BYTES (safe read)
                size_t to_read = SIGN_LEN + FOLLOW_BYTES;
                unsigned char *outbuf = malloc(to_read);
                if (!outbuf) {
                    fprintf(stderr, "malloc failed for outbuf\n");
                    free(buf);
                    fclose(fp);
                    return 6;
                }

                if (fseeko(fp, (off_t)match_offset, SEEK_SET) != 0) {
                    fprintf(stderr, "fseeko failed: %s\n", strerror(errno));
                    free(outbuf);
                    free(buf);
                    fclose(fp);
                    return 7;
                }

                size_t got = fread(outbuf, 1, to_read, fp);
                print_hex_ascii(outbuf, got, match_offset);
                free(outbuf);

                // Now extract the full PNG into imgs/img_{matches+1}.png
                if (extract_png(fp, match_offset, matches + 1) != 0) {
                    fprintf(stderr, "Failed to extract PNG at offset %" PRIu64 "\n", match_offset);
                    // continue scanning anyway (but don't crash)
                } else {
                    matches++;
                }

                // After extraction, restore main scanning position:
                if (fseeko(fp, (off_t)(file_offset + read_bytes), SEEK_SET) != 0) {
                    fprintf(stderr, "fseeko restore failed: %s\n", strerror(errno));
                    free(buf);
                    fclose(fp);
                    return 8;
                }
            }
        }

        if (matches >= (size_t)max_matches) break;

        // Prepare overlap and read next chunk
        if (read_bytes >= OVERLAP) {
            memmove(buf, buf + read_bytes - OVERLAP, OVERLAP);
            size_t next_read = fread(buf + OVERLAP, 1, CHUNK_SIZE, fp);
            file_offset += read_bytes - OVERLAP;
            read_bytes = OVERLAP + next_read;
        } else {
            // very small tail case
            memmove(buf, buf + read_bytes - read_bytes, read_bytes); // noop but explicit
            size_t next_read = fread(buf + read_bytes, 1, CHUNK_SIZE, fp);
            file_offset += read_bytes;
            read_bytes = read_bytes + next_read;
        }
    }

    if (matches == 0) {
        printf("No PNG signature found in %s (from start_offset %" PRIu64 ")\n", path, (uint64_t)start_offset);
    } else {
        printf("Total PNG signatures found/extracted: %zu (stopped at max_matches=%ld)\n", matches, max_matches);
    }

    free(buf);
    fclose(fp);
    return 0;
}
