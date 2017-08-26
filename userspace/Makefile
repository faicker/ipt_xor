# make libxt_XOR.so
# copy to /lib64/xtables/
IDIR =../include
CFLAGS = -O2 -Wall -I$(IDIR)
lib%.so: lib%.o
	gcc -shared -o $@ $^
lib%.o: lib%.c
	gcc ${CFLAGS} -fPIC -c -o $@ $<
