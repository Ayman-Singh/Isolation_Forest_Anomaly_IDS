CLANG ?= clang
BPFTOOL ?= bpftool

# Hardcode libbpf flags since pkg-config is missing
LIBBPF_CFLAGS := 
LIBBPF_LIBS := -lbpf

all: xdp_prog.o manager

xdp_prog.o: xdp_prog.c common.h
	$(CLANG) -O2 -g -target bpf -I/usr/include/x86_64-linux-gnu -c xdp_prog.c -o xdp_prog.o

manager: manager.c common.h
	$(CLANG) -O2 -g manager.c -o manager $(LIBBPF_LIBS)

clean:
	rm -f xdp_prog.o manager
