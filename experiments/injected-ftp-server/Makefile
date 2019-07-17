CC=arm-linux-gcc
CFLAGS=-c -Wall -o0
LDFLAGS=-lm
SOURCES=server.c handles.c
OBJECTS=$(SOURCES:.cpp=.o)
EXECUTABLE=ftp

$(EXECUTABLE): $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -rf *.o ftp
