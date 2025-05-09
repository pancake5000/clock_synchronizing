CC     = g++
CFLAGS = -Wall -Wextra -O2 -std=c++17

TARGET1 = serwer

all: $(TARGET1)

$(TARGET1): $(TARGET1).o err.o
	$(CC) $(CFLAGS) -o $@ $^

$(TARGET1).o: $(TARGET1).cpp komunikaty.h err.h
	$(CC) $(CFLAGS) -c -o $@ $<
err.o: err.cpp err.h
	$(CC) $(CFLAGS) -c -o $@ $<
clean:
	rm -f $(TARGET1) *.o *~