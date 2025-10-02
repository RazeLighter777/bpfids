bpfids.o: bpfids.c bpfidsrules.c
	$(BPFCC) $(BPFCFLAGS) -c bpfids.c
bpfidsrules.c:
	cargo run -- build
clean:
	rm -f bpfidsrules.c bpfids.o
.PHONY: all clean
load: bpfids.o 
	sudo ip link set dev $(IFACE) xdp obj bpfids.o sec xdp
unload:
	sudo ip link set dev $(IFACE) xdp off
