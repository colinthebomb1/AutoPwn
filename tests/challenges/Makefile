CC = gcc

CFLAGS_RET2WIN    = -fno-stack-protector -no-pie -z execstack -z norelro
CFLAGS_RET2LIBC   = -fno-stack-protector -no-pie -z relro
CFLAGS_RET2LIBC_PIE   = -fno-stack-protector -pie -z relro
CFLAGS_RET2LIBC_PIE_CANARY = -fstack-protector-all -pie -z relro
CFLAGS_SHELLCODE  = -fno-stack-protector -no-pie -z execstack -z norelro \
                    -DLEVELNAME='"stack-five-local"'
CFLAGS_FMTREAD    = -fno-stack-protector -no-pie -z norelro -Wno-format-security
CFLAGS_FMTWRITE   = -fno-stack-protector -no-pie -z norelro -Wno-format-security
CFLAGS_HEAP       = -fno-stack-protector -no-pie -z relro -Wno-format-security

BINARIES = ret2win_x64 ret2libc_x64 ret2libc_real_x64 ret2libc_pie_real_x64 ret2libc_pie_canary_real_x64 shellcode_x64 format_read_x64 format_write_x64 heap_tcache_poison_x64

all: $(BINARIES)

ret2win_x64: ret2win.c
	$(CC) $(CFLAGS_RET2WIN) -o $@ $<

ret2libc_x64: ret2libc.c
	$(CC) $(CFLAGS_RET2LIBC) -o $@ $<

ret2libc_real_x64: ret2libc_real.c
	$(CC) $(CFLAGS_RET2LIBC) -o $@ $<

ret2libc_pie_real_x64: ret2libc_pie_real.c
	$(CC) $(CFLAGS_RET2LIBC_PIE) -o $@ $<

ret2libc_pie_canary_real_x64: ret2libc_pie_canary_real.c
	$(CC) $(CFLAGS_RET2LIBC_PIE_CANARY) -o $@ $<

shellcode_x64: shellcode.c
	$(CC) $(CFLAGS_SHELLCODE) -o $@ $<

format_read_x64: format_read.c
	$(CC) $(CFLAGS_FMTREAD) -o $@ $<

format_write_x64: format_write.c
	$(CC) $(CFLAGS_FMTWRITE) -o $@ $<

heap_tcache_poison_x64: heap_tcache_poison.c
	$(CC) $(CFLAGS_HEAP) -o $@ $<

clean:
	rm -f $(BINARIES)

.PHONY: all clean
