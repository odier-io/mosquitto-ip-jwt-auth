all:
	gcc -shared -fPIC -O3 -I ./include -o ami-auth.so ami-auth.c ./lib/libl8w8jwt.a ./lib/libmbedcrypto.a ./lib/libmbedx509.a ./lib/libmbedtls.a
