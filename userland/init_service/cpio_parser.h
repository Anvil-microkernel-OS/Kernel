#ifndef CPIO_PARSER
#define CPIO_PARSER

#include "../libOs/include/shared.h"

typedef struct {
    char magic[6];
    char ino[8];
    char mode[8];
    char uid[8];
    char gid[8];
    char nlink[8];
    char mtime[8];
    char filesize[8];
    char devmajor[8];
    char devminor[8];
    char rdevmajor[8];
    char rdevminor[8];
    char namesize[8];
    char check[8];
} CpioHeader;

static uint32_t parse_hex8(const char *s) {
    uint32_t val = 0;
    for (int i = 0; i < 8; i++) {
        char c = s[i];
        uint32_t d;
        if (c >= '0' && c <= '9')      d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else d = 0;
        val = (val << 4) | d;
    }
    return val;
}

static uint32_t align4(uint32_t v) {
    return (v + 3) & ~3;
}

static int streq(const char *a, const char *b) {
    while (*a && *b) {
        if (*a != *b) return 0;
        a++; b++;
    }
    return *a == *b;
}

// Проверяет, заканчивается ли строка a на суффикс b
static int ends_with(const char *a, const char *b) {
    int alen = 0, blen = 0;
    const char *p;
    for (p = a; *p; p++) alen++;
    for (p = b; *p; p++) blen++;
    if (blen > alen) return 0;
    return streq(a + alen - blen, b);
}

static const uint8_t *cpio_find(const uint8_t *archive, uint64_t archive_size,
                                const char *name, uint64_t *out_size) {
    const uint8_t *p = archive;
    const uint8_t *end = archive + archive_size;

    while (p + 110 <= end) {
        const CpioHeader *hdr = (const CpioHeader *)p;

        if (hdr->magic[0] != '0' || hdr->magic[1] != '7' ||
            hdr->magic[2] != '0' || hdr->magic[3] != '7' ||
            hdr->magic[4] != '0' || hdr->magic[5] != '1')
            return 0;

        uint32_t filesize = parse_hex8(hdr->filesize);
        uint32_t namesize = parse_hex8(hdr->namesize);

        const char *fname = (const char *)(p + 110);
        const uint8_t *data = p + align4(110 + namesize);

        if (streq(fname, "TRAILER!!!"))
            return 0;

        if (data + filesize > end)
            return 0;

        if (streq(fname, name) || ends_with(fname, name)) {
            *out_size = filesize;
            return data;
        }

        p = data + align4(filesize);
    }

    return 0;
}

#endif //CPIO_PARSER
