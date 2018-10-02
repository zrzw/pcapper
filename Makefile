CC = clang++ -Wall -g -std=c++14
LIBS = /usr/lib/x86_64-linux-gnu/libpcap.so
INCLUDE = ./include

pcapper_test: main.o pcapper.o
	$(CC) -o pcapper_test main.o pcapper.o $(LIBS)

main.o: src/main.cpp $(INCLUDE)/pcapper.h
	$(CC) -c src/main.cpp -I$(INCLUDE)

pcapper.o: src/pcapper.cpp $(INCLUDE)/pcapper.h
	$(CC) -c src/pcapper.cpp -I$(INCLUDE)

clean:
	rm *.o
