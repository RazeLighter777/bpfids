bpfids.o: bpfids.c bpfidsrules.c
	$(CC) $(CFLAGS) -c bpfids.c
bpfisrules.c:
	cargo run -- build
clean:
	rm -f bpfids bpfids.o
.PHONY: all clean
load: bpfids.o
	sudo ip link set dev $(IFACE) xdp obj bpfids.o sec xdp
unload:
	sudo ip link set dev $(IFACE) xdp off