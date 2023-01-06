LDLIBS += -lpcap

all: AIRODUMP

mac.o : mac.h mac.cpp

AIRODUMP : airodump.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f airodump *.o
