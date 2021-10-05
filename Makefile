all:
	gcc -std=c99 -O3 -fPIC -shared -I ./include -D_POSIX_C_SOURCE -o ./ip-jwt-auth.so ./ip-jwt-auth.c \
./lib/libl8w8jwt.a \
./lib/libmbedcrypto.a \
./lib/libmbedx509.a \
./lib/libmbedtls.a

deps:
	./make_dependencies.sh

clean:
	rm -fr ./lib ./include ./ip-jwt-auth.so
