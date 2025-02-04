all: vmlinux xdp_drop_port.o 

vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h


CLANG = clang
CFLAGS = -O2 -g -target bpf \
         -I/usr/include 

xdp_drop_port.o: xdp_drop_port.c
	$(CLANG) $(CFLAGS) -c $< -o $@

.PHONY:
clean:
	rm -rf vmlinux.h
	rm -rf xdp_drop_port.o
