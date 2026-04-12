CC = gcc

CFLAGS = -nostdlib -nostdinc -ffreestanding -O2 \
         -fno-stack-protector -mno-red-zone \
         -fno-builtin -static \
         -Wl,-Ttext=0x400000 \
         -Wl,--build-id=none \
         -Wl,-e,_start \
         -Wl,-T,link.ld \
         -nodefaultlibs

all: server.elf

server.elf: server.c
	$(CC) $(CFLAGS) -o $@ $<


clean:
	rm -f *.elf
