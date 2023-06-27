LDLIBS=-lpcap

all: deauth-attack


deauth-attack.o: mac.h deauth-attack.cpp


mac.o : mac.h mac.cpp

deauth-attack: deauth-attack.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f deauth-attack *.o