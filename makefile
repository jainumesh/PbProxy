
default: pbproxy

	
pbproxy: pbproxy.c
	gcc -I /usr/lib/x86_64-linux-gnu/openssl-1.0.0 -g -o pbproxy pbproxy.c -ldl -lcrypto -lpthread
	mv pbproxy /usr/local/bin
clean:
	-rm -f pbproxy.o
	-rm -f pbproxy
	
	
