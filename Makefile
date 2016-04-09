MACHINE := $(shell uname -smo | sed 's/ /-/g')
CC := gcc
CXX := g++
CFLAGS += -g -std=gnu99
CXXFLAGS += -Wno-write-strings
CPPFLAGS += -Wall
LIBS += -lncurses
TESTS = util_test

# Filesystem layout
SRCDIR := .
INCDIR := .
BUILDDIR := build
TARGETDIR := bin
TESTDIR := unittests

sources = $(wildcard *.c)
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
	find . -name "*.h" -o -name "*.c" | etags -

test : $(TESTS)

$(TESTDIR)/util_test.o : $(TESTDIR)/util_test.c
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $(TESTDIR)/util_test.c -o $@

util_test : $(TESTDIR)/util_test.o
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -lgtest_main -lgtest -lpthread  $< -o $(TESTDIR)/$@
