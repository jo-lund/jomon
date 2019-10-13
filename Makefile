srcdir := decoder ui
incdir := decoder ui
BUILDDIR := build
TARGETDIR := bin
MACHINE := $(shell uname -s)
STRIP := strip
CC := gcc
CXX := g++
CFLAGS += -std=gnu11
CXXFLAGS += -Wno-write-strings
CPPFLAGS += -Wall -Wextra -Wno-override-init $(addprefix -I,$(incdir))
LIBS += -lncurses -lGeoIP

sources = $(wildcard *.c decoder/*.c ui/*.c)
ifeq ($(MACHINE), Linux)
	sources += $(wildcard linux/*.c)
endif
objects = $(patsubst %.c,$(BUILDDIR)/%.o,$(sources))

debug : CFLAGS += -g
debug : CPPFLAGS += -fsanitize=address -fno-omit-frame-pointer
debug : monitor

release : CFLAGS += -O2
release : monitor
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

.PHONY : clean
clean :
	rm -rf bin
	rm -rf build

.PHONY : tags
tags :
	@find . -name "*.h" -o -name "*.c" | etags -
