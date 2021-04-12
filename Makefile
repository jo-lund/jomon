ifeq ($(wildcard ./config.mk),)
    $(error "configure needs to be run before make. For help, use: ./configure -h")
endif

include config.mk

srcdir := decoder ui
incdir := decoder ui
testdir := tests
BUILDDIR := build
TARGETDIR := bin
MACHINE := $(shell uname -s)
STRIP := strip
CC := gcc
CFLAGS += -std=gnu11
CPPFLAGS += -Wall -Wextra -Wno-override-init $(addprefix -I,$(incdir))
LIBS += -lncurses
ifeq ($(CONFIG_GEOIP),0)
    sources = $(filter-out geoip.c,$(wildcard *.c decoder/*.c ui/*.c))
else
    LIBS += -lGeoIP
    sources = $(wildcard *.c decoder/*.c ui/*.c)
endif
ifeq ($(MACHINE), Linux)
    sources += $(wildcard linux/*.c)
endif
objects = $(patsubst %.c,$(BUILDDIR)/%.o,$(sources))
objects += $(BUILDDIR)/bpf/bpf_parser.o $(BUILDDIR)/bpf/bpf_lexer.o $(BUILDDIR)/bpf/bpf.o $(BUILDDIR)/bpf/pcap_lexer.o \
  $(BUILDDIR)/bpf/pcap_parser.o $(BUILDDIR)/bpf/genasm.o
test-objs = $(patsubst %.c,%.o,$(wildcard $(testdir)/*.c))
bpf-objs = $(BUILDDIR)/bpf/bpf_parser.o $(BUILDDIR)/bpf/bpf_lexer.o $(BUILDDIR)/bpf/bpf.o \
  $(BUILDDIR)/bpf/pcap_lexer.o $(BUILDDIR)/bpf/pcap_parser.o $(BUILDDIR)/stack.o $(BUILDDIR)/vector.o \
  $(BUILDDIR)/hashmap.o $(BUILDDIR)/mempool.o $(BUILDDIR)/debug_file.o $(BUILDDIR)/util.o $(BUILDDIR/stack.o) \
  $(BUILDDIR)/bpf/genasm.o
test-objs += $(bpf-objs)

.PHONY : all
all : debug

.PHONY : debug
debug : CFLAGS += -g -fsanitize=address -fno-omit-frame-pointer
debug : CPPFLAGS += -DMONITOR_DEBUG
debug : $(TARGETDIR)/monitor

.PHONY : release
release : CFLAGS += -O3
release : $(TARGETDIR)/monitor
	@$(STRIP) --strip-all --remove-section .comment $(TARGETDIR)/monitor

$(TARGETDIR)/monitor : $(objects)
	@mkdir -p $(TARGETDIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $(objects) $(LIBS)

bpf/bpf_lexer.c : bpf/bpf_lexer.re
	re2c -W $< -o $@

bpf/pcap_lexer.c : bpf/pcap_lexer.re
	re2c -T -W $< -o $@

# Compile and generate dependency files
$(BUILDDIR)/%.o : %.c
	@mkdir -p $(dir $@)
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@
	$(CC) -MM $*.c > $(BUILDDIR)/$*.d
	@sed -i 's|.*:|$(BUILDDIR)/$*.o:|' $(BUILDDIR)/$*.d # prefix target with BUILDDIR

# Include dependency info for existing object files
-include $(objects:.o=.d)
-include $(bpf-objs:.o=.d)

.PHONY : clean
clean :
	rm -rf bin
	rm -rf build
	rm -f $(test-objs) $(testdir)/test
	rm -f bpf/lexer.c bpf/pcap_lexer.c

.PHONY : distclean
distclean : clean
	rm -f config.h config.mk

.PHONY : testclean
testclean :
	rm -f $(test-objs) $(testdir)/test

.PHONY : bpfclean
bpfclean :
	rm -f $(bpf-objs) bpf/lexer.c bpf/pcap_lexer.c


.PHONY : tags
tags :
	@find . -name "*.h" -o -name "*.c" | etags -

test : CFLAGS += -O3
test : $(testdir)/test
	@$<

$(testdir)/test : $(test-objs)
	@$(CC) $(CFLAGS) $(CPPFLAGS) $(test-objs) -o $@ -lcheck -lm -lpthread -lrt
