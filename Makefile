ifeq ($(wildcard ./config.mk),)
    $(error "configure needs to be run before make. For help, use: ./configure -h")
endif

include config.mk

TESTDIR := tests
BUILDDIR := build
TARGETDIR := bin
MACHINE := $(shell uname -s)
STRIP := strip
CFLAGS += -std=gnu11 -fwrapv -Wall -Wextra -Wno-override-init
CPPFLAGS += -iquote $(CURDIR) -DVERSION=\"$(VERSION)\"
LIBS := -lncurses
UNIT_LIBS := -lcheck -lm -lpthread -lrt
ifneq ($(wildcard /etc/debian_version),)
     UNIT_LIBS += -lsubunit
endif
sources = $(filter-out geoip.c,$(wildcard *.c decoder/*.c ui/*.c ui/ncurses/*.c))
ifeq ($(HAVE_GEOIP),1)
    LIBS += -lGeoIP
    sources += geoip.c
    CPPFLAGS += -DHAVE_GEOIP
endif
ifeq ($(HAVE_OBSTACK),1)
    CPPFLAGS += -DHAVE_OBSTACK
else
    sources += $(wildcard compat/*.c)
endif
ifeq ($(MACHINE),Linux)
    sources += $(wildcard linux/*.c)
else
ifeq ($(MACHINE),FreeBSD)
    sources += $(wildcard bsd/*.c)
endif
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
test-objs = $(patsubst %.c,%.o,$(wildcard $(TESTDIR)/*.c))
test-objs += $(bpf-objs) \
	$(BUILDDIR)/stack.o \
	$(BUILDDIR)/vector.o \
	$(BUILDDIR)/hashmap.o \
	$(BUILDDIR)/mempool.o \
	$(BUILDDIR)/debug.o \
	$(BUILDDIR)/util.o \
	$(BUILDDIR/stack.o) \
	$(BUILDDIR)/string.o \
	$(BUILDDIR)/rbtree.o

.PHONY : all
all : release

.PHONY : debug
debug : CFLAGS += -g -fsanitize=address,undefined -fno-omit-frame-pointer
debug : CPPFLAGS += -DMONITOR_DEBUG
debug : $(TARGETDIR)/monitor

.PHONY : release
release : CFLAGS += -O2
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
	$(CC) -MM $(CPPFLAGS) $*.c > $(BUILDDIR)/$*.d
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
	@rm -f $(test-objs) $(TESTDIR)/test
	@rm -f bpf/lexer.c bpf/pcap_lexer.c

.PHONY : distclean
distclean : clean
	@rm -f config.h config.mk

.PHONY : testclean
testclean :
	@echo "Cleaning..."
	@rm -f $(test-objs) $(TESTDIR)/test

.PHONY : tags
tags :
	@echo "Generating tags..."
	@find . -name "*.h" -o -name "*.c" | etags -

test : CFLAGS += -Os
test : $(TESTDIR)/test
	@$<

$(TESTDIR)/test : $(test-objs)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(test-objs) -o $@ $(LIBS) $(UNIT_LIBS)
