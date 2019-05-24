FLAGS+= -Wall -Wextra -O2 -pedantic -std=c++17 -g
BOOST= -lboost_program_options
SERVER_LIBS= -lstdc++fs

all: netstore-client netstore-server

netstore-client: netstore-client.o
	g++ netstore-client.o $(BOOST) -o netstore-client

netstore-server: netstore-server.o
	g++ netstore-server.o $(BOOST) $(SERVER_LIBS) -o netstore-server

netstore-client.o: client.cc netstore.h
	g++ $(FLAGS) client.cc -c -o netstore-client.o

netstore-server.o: server.cc netstore.h
	g++ $(FLAGS) server.cc -c -o netstore-server.o

.PHONY : clean

# -> $@ $@

clean:
	$(RM) netstore-server netstore-client *.o