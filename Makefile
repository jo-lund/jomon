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
test-objs = $(patsubst %.c,%.o,$(wildcard $(testdir)/*.c))

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

# Compile and generate dependency files
$(BUILDDIR)/%.o : %.c
	@mkdir -p $(dir $@)
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@
	$(CC) -MM $*.c > $(BUILDDIR)/$*.d
	@sed -i 's|.*:|$(BUILDDIR)/$*.o:|' $(BUILDDIR)/$*.d # prefix target with BUILDDIR

# Include dependency info for existing object files
-include $(objects:.o=.d)

.PHONY : clean
clean :
	rm -rf bin
	rm -rf build
	rm -f $(test-objs) $(testdir)/test

.PHONY : distclean
distclean : clean
	rm -f config.h config.mk

.PHONY : testclean
testclean :
	rm -f $(test-objs) $(testdir)/test

.PHONY : tags
tags :
	@find . -name "*.h" -o -name "*.c" | etags -

test : $(testdir)/test
	@$<

$(testdir)/test : $(test-objs)
	$(CC) $(CPPFLAGS) $< -o $@  -lcheck -lm -lpthread -lrt -lsubunit
