all: vmlinux xdp_drop_icmp.o 

vmlinux:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

xdp_drop_icmp.o: xdp_drop_icmp.c
	clang -target bpf -Wall -O2 -c $<



.PHONY:
clean:
	rm -rf vmlinux.h
	rm -rf xdp_drop_icmp.o
	rm -rf example.skel.h
