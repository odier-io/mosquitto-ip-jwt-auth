all:
	gcc -std=c99 -O3 -fPIC -shared -I ./include -D_POSIX_C_SOURCE -o ./ami-auth.so ./ami-auth.c \
./lib/libl8w8jwt.a \
./lib/libmbedcrypto.a \
./lib/libmbedx509.a \
./lib/libmbedtls.a

deps:
	./make_dependencies.sh

clean:
	rm -fr ./lib ./include ./ami-auth.so
