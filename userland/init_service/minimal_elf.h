#ifndef ELF_LOADER
#define ELF_LOADER

#include "../libOs/include/shared.h"

// ELF64 structures
typedef struct {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
} Elf64_Phdr;

#define PT_LOAD 1
#define PF_X 0x1
#define PF_W 0x2
#define PF_R 0x4

static uint32_t elf_flags_to_map(uint32_t p_flags) {
    uint32_t f = MAP_READ;
    if (p_flags & PF_W) f |= MAP_WRITE;
    if (p_flags & PF_X) f |= MAP_EXEC;
    return f;
}

static void memcpy_simple(void *dst, const void *src, uint64_t n) {
    uint8_t *d = (uint8_t *)dst;
    const uint8_t *s = (const uint8_t *)src;
    for (uint64_t i = 0; i < n; i++) d[i] = s[i];
}

static void memset_simple(void *dst, uint8_t val, uint64_t n) {
    uint8_t *d = (uint8_t *)dst;
    for (uint64_t i = 0; i < n; i++) d[i] = val;
}

static int64_t load_elf(const uint8_t *elf_data, uint64_t elf_size,
                        uint64_t self_vspace, uint64_t slave_vspace) {
    const Elf64_Ehdr *ehdr = (const Elf64_Ehdr *)elf_data;
    
    // Проверить ELF magic
    if (ehdr->e_ident[0] != 0x7f || ehdr->e_ident[1] != 'E' ||
        ehdr->e_ident[2] != 'L'  || ehdr->e_ident[3] != 'F') {
        printf("Invalid ELF magic\n");
        return -1;
    }

    const Elf64_Phdr *phdrs = (const Elf64_Phdr *)(elf_data + ehdr->e_phoff);
    
    for (int i = 0; i < ehdr->e_phnum; i++) {
        const Elf64_Phdr *ph = &phdrs[i];
        
        if (ph->p_type != PT_LOAD) continue;
        if (ph->p_memsz == 0) continue;

        int64_t vmo = vmo_create(ph->p_memsz, VmoPhysical);
        if (vmo < 0) {
            printf("load_elf: vmo_create failed for segment %d\n", i);
            return -1;
        }

        if (ph->p_filesz > 0) {
            int64_t written = vmo_write(
                vmo,                              // vmo_cap
                (void *)(elf_data + ph->p_offset),  // data_ptr
                0,                                // offset in VMO
                ph->p_filesz                      // how much
            );
            
            if (written < 0 || written != (int64_t)ph->p_filesz) {
                printf("load_elf: vmo_write failed for segment %d\n", i);
                return -1;
            }
        }

        if (ph->p_memsz > ph->p_filesz) {
            //todo fill zero
        }

         mmap_args_t mmap_args = {
            .vscape_cap = slave_vspace,
            .vmo_cap = (uint64_t)vmo,
            .vaddr = ph->p_vaddr,              
            .size = ph->p_memsz,
            .vmo_offset = 0,
            .flags = elf_flags_to_map(ph->p_flags)
        };
        
        uint64_t mapped = vma_map(&mmap_args);
        if (mapped < 0) {
            printf("load_elf: vma_map(slave) failed for segment %d at 0x%lx\n",
                   i, ph->p_vaddr);
            return -1;
        }
    }

    return (int64_t)ehdr->e_entry;
}

#endif //ELF_LOADER
