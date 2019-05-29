CXXFLAGS+= -Wall -Wextra -pedantic -std=c++17 -g #-O2
LDLIBS= -lstdc++ -lstdc++fs -lboost_program_options -lpthread

all: netstore-client netstore-server

netstore-client: netstore-client.o netstore-boost.o netstore.o

netstore-server: netstore-server.o netstore-boost.o netstore.o

netstore-boost.o: netstore-boost.h

netstore-client.o: netstore.h

netstore-server.o: netstore.h

netstore.o : netstore.h

.PHONY : clean

# -> $@ $^

clean:
	$(RM) netstore-server netstore-client *.o