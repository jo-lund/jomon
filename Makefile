srcdir := decoder ui
incdir := decoder ui
BUILDDIR := build
TARGETDIR := bin

CC := gcc
CXX := g++
CFLAGS += -g -std=gnu99
CXXFLAGS += -Wno-write-strings
CPPFLAGS += -Wall -Wextra -Wno-override-init $(addprefix -I,$(incdir))
LIBS += -lmenu -lncurses
TESTS = util_test

sources = $(wildcard *.c decoder/*.c ui/*.c)
objects = $(patsubst %.c,$(BUILDDIR)/%.o,$(sources))

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
