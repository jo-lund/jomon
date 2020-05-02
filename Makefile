srcdir := decoder ui
incdir := decoder ui
BUILDDIR := build
TARGETDIR := bin
MACHINE := $(shell uname -s)
STRIP := strip
CC := gcc
CXX := g++
CFLAGS += -std=gnu11
CPPFLAGS += -Wall -Wextra -Wno-override-init $(addprefix -I,$(incdir))
LIBS += -lncurses -lGeoIP

sources = $(wildcard *.c decoder/*.c ui/*.c)
ifeq ($(MACHINE), Linux)
	sources += $(wildcard linux/*.c)
endif
objects = $(patsubst %.c,$(BUILDDIR)/%.o,$(sources))

all : debug

debug : CFLAGS += -g -fsanitize=address -fno-omit-frame-pointer
debug : CPPFLAGS += -DMONITOR_DEBUG
debug : check-build monitor

release : CFLAGS += -O3
release : check-build monitor
	@$(STRIP) --strip-all --remove-section .comment $(TARGETDIR)/monitor

monitor : $(objects)
	@mkdir -p $(TARGETDIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $(TARGETDIR)/monitor $(objects) $(LIBS)

# Compile and generate dependency files
$(BUILDDIR)/%.o : %.c
	@mkdir -p $(dir $@)
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@
	$(CC) -MM $*.c > $(BUILDDIR)/$*.d
	@sed -i 's|.*:|$(BUILDDIR)/$*.o:|' $(BUILDDIR)/$*.d # prefix target with BUILDDIR

# Include dependency info for existing object files
-include $(objects:.o=.d)

.PHONY : check-build
check-build :
	@./build.sh

.PHONY : clean
clean :
	rm -rf bin
	rm -rf build

.PHONY : tags
tags :
	@find . -name "*.h" -o -name "*.c" | etags -
