test.exe : test.c luabind.c
	gcc -g -Wall -o $@ $^ -I/usr/local/include -L/usr/local/bin -llua53

clean :
	rm test.exe