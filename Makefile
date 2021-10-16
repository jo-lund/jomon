ifeq ($(wildcard ./config.mk),)
    $(error "configure needs to be run before make. For help, use: ./configure -h")
endif

include config.mk

incdir := decoder ui
testdir := tests
BUILDDIR := build
TARGETDIR := bin
MACHINE := $(shell uname -s)
STRIP := strip
CFLAGS += -std=gnu11 -fwrapv -g
CPPFLAGS += -Wall -Wextra -Wno-override-init $(addprefix -I,$(incdir))
LIBS += -lncurses
ifeq ($(CONFIG_GEOIP),0)
    sources = $(filter-out geoip.c,$(wildcard *.c decoder/*.c ui/*.c))
else
    LIBS += -lGeoIP
    sources = $(wildcard *.c decoder/*.c ui/*.c)
endif
ifeq ($(HAVE_OBSTACK),0)
    sources += $(wildcard compat/*.c)
else
    CPPFLAGS += -DHAVE_OBSTACK
endif
ifeq ($(MACHINE),Linux)
    sources += $(wildcard linux/*.c)
else ($(MACHINE),FreeBSD)
    sources += $(wildcard bsd/*.c)
endif
objects = $(patsubst %.c,$(BUILDDIR)/%.o,$(sources))
bpf-objs = \
	$(BUILDDIR)/bpf/bpf_parser.o \
	$(BUILDDIR)/bpf/bpf_lexer.o \
	$(BUILDDIR)/bpf/bpf.o \
	$(BUILDDIR)/bpf/pcap_lexer.o \
	$(BUILDDIR)/bpf/pcap_parser.o \
	$(BUILDDIR)/bpf/genasm.o
objects += $(bpf-objs)
test-objs = $(patsubst %.c,%.o,$(wildcard $(testdir)/*.c))
test-objs += $(bpf-objs) \
	$(BUILDDIR)/stack.o \
	$(BUILDDIR)/vector.o \
	$(BUILDDIR)/hashmap.o \
	$(BUILDDIR)/mempool.o \
	$(BUILDDIR)/debug.o \
	$(BUILDDIR)/util.o \
	$(BUILDDIR/stack.o) \
	$(BUILDDIR)/string.o

.PHONY : all
all : release

.PHONY : debug
debug : CFLAGS += -fsanitize=address -fno-omit-frame-pointer
debug : CPPFLAGS += -DMONITOR_DEBUG
debug : $(TARGETDIR)/monitor

.PHONY : release
release : CFLAGS += -Os
release : $(TARGETDIR)/monitor

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
	@sed -i -r 's|.*:|$(BUILDDIR)/$*.o:|' $(BUILDDIR)/$*.d # prefix target with BUILDDIR

# Include dependency info for existing object files
-include $(objects:.o=.d)
-include $(bpf-objs:.o=.d)

install :
	@install -sD --strip-program=$(STRIP) bin/monitor $(PREFIX)/bin/monitor

uninstall :
	@rm -f $(PREFIX)/bin/monitor

.PHONY : clean
clean :
	@echo "Cleaning..."
	@rm -rf bin
	@rm -rf build
	@rm -f $(test-objs) $(testdir)/test
	@rm -f bpf/lexer.c bpf/pcap_lexer.c

.PHONY : distclean
distclean : clean
	@rm -f config.h config.mk

.PHONY : testclean
testclean :
	@echo "Cleaning..."
	@rm -f $(test-objs) $(testdir)/test

.PHONY : tags
tags :
	@echo "Generating tags..."
	@find . -name "*.h" -o -name "*.c" | etags -

test : CFLAGS += -Os
test : $(testdir)/test
	@$<

$(testdir)/test : $(test-objs)
	@$(CC) $(CFLAGS) $(CPPFLAGS) $(test-objs) -o $@ -lcheck -lm -lpthread -lrt
