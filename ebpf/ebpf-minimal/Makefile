# Makefile - build the XDP object
CLANG=clang
LLC=llc
TARGET=xdp_fw.o
SRC=xdp_fw.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CLANG) -O2 -g -target bpf -D__BPF_TRACING__ -c $(SRC) -o $(TARGET)

clean:
	rm -f $(TARGET)
