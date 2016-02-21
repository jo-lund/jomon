MACHINE := $(shell uname -smo | sed 's/ /-/g')
HAVE_PCAP := 0
CC := gcc
CFLAGS += -g -std=gnu99
CPPFLAGS += -Wall
LIBS += -lncurses

# Filesystem layout
SRCDIR := .
INCDIR := .
BUILDDIR := build
TARGETDIR := bin

ifeq ($(HAVE_PCAP), 1)
  sources = $(wildcard *.c)
  LIBS += -lpcap
else
  sources = $(filter-out pcap%, $(wildcard *.c))
endif

objects = $(patsubst %.c,$(BUILDDIR)/%.o,$(sources))

monitor : $(objects)
	@mkdir -p $(TARGETDIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $(TARGETDIR)/monitor $(objects) $(LIBS)

# Compile and generate dependency files
$(BUILDDIR)/%.o : %.c
	@mkdir -p $(dir $@)
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@
	$(CC) -MM $*.c > $(BUILDDIR)/$*.d

# Include dependency info for existing object files
-include $(objects:.o=.d)

.PHONY : clean
clean :
	rm -rf bin
	rm -rf build
