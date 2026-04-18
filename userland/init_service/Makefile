# Include libOs definitions
include ../libOs/includeme.mk

CC = gcc
OBJCOPY = objcopy
CFLAGS = -nostdlib -nostdinc -ffreestanding -O2 \
         -fno-stack-protector -mno-red-zone \
         -fno-builtin -static \
         -Wl,-Ttext=0x400000 \
         -Wl,--build-id=none \
         -Wl,-e,_start \
         -Wl,-T,link.ld \
         -nodefaultlibs

.INTERMEDIATE: init.elf

all: init.bin

init.elf: server.c
	# Make sure libOs is built
	$(MAKE) -C ../libOs/ -f ../libOs/subproject.mk

	# Finally, link libOs with server.
	$(CC) $(CFLAGS) -o $@ $< $(LIBOS_LIB)

init.bin: init.elf
	$(OBJCOPY) -O binary $< $@

clean:
	rm -f *.elf *.bin
