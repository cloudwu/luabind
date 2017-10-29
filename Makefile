test: test.c luabind.c
	gcc -g -Wall -o $@ $^ -I/usr/local/include -L/usr/local/lib -llua

clean :
	rm test