CC     = g++
CFLAGS = -Wall -Wextra -O2 -std=gnu17

TARGET1 = serwer

all: $(TARGET1)

$(TARGET1): $(TARGET1).o
$(TARGET1).o: $(TARGET1).cpp

clean:
	rm -f $(TARGET1) *.o *~