MACHINE:= $(shell uname -smo | sed 's/ /-/g')
HAVE_PCAP := 0
CC := gcc

ifeq ($(HAVE_PCAP), 1)
  sources = $(wildcard *.c)
  LIBS = -lpcap
else
  sources = $(filter-out pcap%, $(wildcard *.c))
endif

objects = $(subst .c,.o,$(sources))

monitor : $(objects)
	gcc -Wall -g $(LIBS) -o monitor $(objects)

network_monitor.o : misc.h
pcap_handler.o : misc.h pcap_handler.h

.PHONY : clean
clean :
	rm -f *.o monitor
