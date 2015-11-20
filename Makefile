MACHINE := $(shell uname -smo | sed 's/ /-/g')
HAVE_PCAP := 0
CC := gcc
CFLAGS += -g -std=gnu99
CPPFLAGS += -Wall
LIBS += -lncurses

ifeq ($(HAVE_PCAP), 1)
  sources = $(wildcard *.c)
  LIBS += -lpcap
else
  sources = $(filter-out pcap%, $(wildcard *.c))
endif

objects = $(subst .c,.o,$(sources))

monitor : $(objects)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(LIBS) -o monitor $(objects)

main.o : misc.h interface.h
pcap_handler.o : misc.h pcap_handler.h
error.c : misc.h

.PHONY : clean
clean :
	rm -f *.o monitor
