wdb:
	gcc -o wdb wdb.c console.c libelf.c -g
clean:
	rm -f *.o wdb
