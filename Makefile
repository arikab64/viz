BPF_CFLAGS := -O2 -g -Wall -target bpf -D__TARGET_ARCH_x86
BPF_LDFLAGS := 

LOADER_CFLAGS := -O2 -g -Wall
LOADER_LDFLAGS := -lelf -lbpf

TARGETS := nf_viz.bpf.o nf_viz_loader

.PHONY: all clean

all: $(TARGETS)

%.bpf.o: %.bpf.c vmlinux.h
	clang $(BPF_CFLAGS) -c $< -o $@ $(BPF_LDFLAGS)

vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@

nf_viz_loader: nf_viz_load.c
	clang $(LOADER_CFLAGS) $< -o $@ $(LOADER_LDFLAGS)

clean:
	rm -f $(TARGETS) vmlinux.h