# Userspace iptables extension
libipt_FULLCONENAT.so: libipt_FULLCONENAT.o
	$(CC) -shared -lxtables -o $@ $^
libipt_FULLCONENAT.o: libipt_FULLCONENAT.c
	$(CC) $(CFLAGS) -fPIC -D_INIT=$*_init -c -o $@ $<

# Kernel module: single .ko from three source files
obj-m += fullcone_nat.o
fullcone_nat-objs := fullcone_core.o fullcone_xt.o fullcone_nft.o
