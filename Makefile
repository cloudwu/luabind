tcpsniff: sniff.c tcpsniff.c luabind.c 
	gcc -g -Wall -o $@ $^ -I/usr/local/include -L/usr/local/lib -llua -lpcap

test: test.c luabind.c
	gcc -g -Wall -o $@ $^ -I/usr/local/include -L/usr/local/lib -llua

clean:
	rm -f test
	rm -f tcpsniff
	rm -rf *.dSYM