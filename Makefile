
CXX := g++
LDFLAGS := $(ldflags) `pkg-config --libs $(HOME)/opencv/install/lib/pkgconfig/opencv4.pc` -Wl,--rpath=$(HOME)/opencv/install/lib
CXXFLAGS := -Wall -Iinclude $(cflags) `pkg-config --cflags $(HOME)/opencv/install/lib/pkgconfig/opencv4.pc`
# SRCS := $(wildcard src/*.cpp)
# OBJS := $(patsubst src/%.cpp,obj/%.o,$(SRCS))
# EXES := $(patsubst src/%.cpp,bin/%,$(SRCS))
TESTSRCS := $(wildcard testsrc/*.cpp)
TESTOBJS := $(patsubst testsrc/%.cpp,obj/%.o,$(TESTSRCS))
TESTEXES := $(patsubst testsrc/%.cpp,bin/%,$(TESTSRCS))

.PHONY: all clean objs echo

all: $(EXES) $(TESTEXES) bin/cryption bin/facial_cryption bin/test_md bin/test_crypt

objs: $(OBJS)

echo:
	@echo $(TESTOBJS) $(TESTEXES)

clean :
	rm -f $(TESTOBJS) $(TESTEXES) 

obj/cryption.o: src/cryption.cpp include/cryption.hpp
	$(CXX) -o $@ -c $< $(CXXFLAGS)

obj/test_md.o: src/test/test_md.cpp
	$(CXX) -o $@ -c $< $(CXXFLAGS)

bin/test_md: obj/test_md.o obj/cryption.o
	$(CXX) -o $@ $^ -lpng -lcrypto $(LDFLAGS)

obj/test_crypt.o: src/test/test_crypt.cpp
	$(CXX) -o $@ -c $< $(CXXFLAGS)

bin/test_crypt: obj/test_crypt.o obj/cryption.o
	$(CXX) -o $@ $^ -lpng -lcrypto $(LDFLAGS)

obj/simhash.o: src/simhash.cpp include/lsh.hpp
	$(CXX) -o $@ -c $< $(CXXFLAGS)

obj/facial_cryption.o: src/facial_cryption.cpp include/lsh.hpp include/cryption.hpp
	$(CXX) -o $@ -c $< $(CXXFLAGS)

bin/facial_cryption: obj/facial_cryption.o obj/simhash.o obj/cryption.o
	$(CXX) -o $@ $^ -lpng -lcrypto $(LDFLAGS)


$(TESTOBJS) : obj/%.o : testsrc/%.cpp
	$(CXX) -o $@ -c $^ $(CXXFLAGS)

$(TESTEXES) : bin/% : obj/%.o
	$(CXX) -o $@ $^ $(LDFLAGS)
