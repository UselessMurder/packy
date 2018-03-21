.PHONY: all clean install uinstall

INC_DIR =
LIB_DIR =
LIBS =
CPPFLAGS =
APP =
LASTFLAGS =
COMPILER = clang++
MKFILE_PATH := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))


ifeq ($(OS),Windows_NT)
	LIB_DIR += -L$(MKFILE_PATH)	
	LASTFLAGS += -municode
	APP = main.exe
else
	APP = main
endif

INC_DIR += -I$(MKFILE_PATH)
INC_DIR += -I$(MKFILE_PATH)include
LIBS += -L/usr/lib
LIBS += -lr_asm
LIBS += -lpthread
#LIBS += -llibboost_filesystem-mt
LIBS += -lboost_filesystem
#LIBS += -llibboost_system-mt
LIBS += -lboost_system
LIBS += -lcryptopp
LIBS += -llzo2

CPPFLAGS += -std=c++17 -Wc++17-extensions -Ofast -fopenmp -D_GLIBCXX_PARALLEL -march=native $(INC_DIR)  
#CPPFLAGS += -std=c++17 -static-libstdc++ -O3 $(INC_DIR) 

OBJECTS = objfiles/main.o
OBJECTS += objfiles/packy.o
OBJECTS += objfiles/file.o
OBJECTS += objfiles/base_ld.o
OBJECTS += objfiles/base_pe.o
OBJECTS += objfiles/pe32.o
OBJECTS += objfiles/base_mk.o
OBJECTS += objfiles/compress.o
OBJECTS += objfiles/crypto.o
OBJECTS += objfiles/global_entities.o
OBJECTS += objfiles/pe32_i686.o
OBJECTS += objfiles/binding.o
OBJECTS += objfiles/part.o
OBJECTS += objfiles/memory_piece.o
OBJECTS += objfiles/frame.o
OBJECTS += objfiles/machine_state.o
OBJECTS += objfiles/form.o
OBJECTS += objfiles/invariant.o
OBJECTS += objfiles/base_eg.o
OBJECTS += objfiles/i8086.o
OBJECTS += objfiles/i686.o

all:  $(APP)

clean: 
	rm -rf $(APP) objfiles/*.o

objfiles/main.o: main.cpp
	$(COMPILER) -c -o objfiles/main.o main.cpp $(CPPFLAGS) 

objfiles/packy.o: packy/packy.cpp
	$(COMPILER) -c -o objfiles/packy.o packy/packy.cpp $(CPPFLAGS)

objfiles/file.o: fs/file.cpp
	$(COMPILER) -c -o objfiles/file.o fs/file.cpp $(CPPFLAGS)

objfiles/base_ld.o: ld/base_ld/base_ld.cpp
	$(COMPILER) -c -o objfiles/base_ld.o ld/base_ld/base_ld.cpp $(CPPFLAGS)

objfiles/base_pe.o: ld/pe/base_pe/base_pe.cpp
	$(COMPILER) -c -o objfiles/base_pe.o ld/pe/base_pe/base_pe.cpp $(CPPFLAGS)

objfiles/pe32.o: ld/pe/pe32/pe32.cpp
	$(COMPILER) -c -o objfiles/pe32.o ld/pe/pe32/pe32.cpp $(CPPFLAGS)

objfiles/base_mk.o: mk/base_mk/base_mk.cpp
	$(COMPILER) -c -o objfiles/base_mk.o mk/base_mk/base_mk.cpp $(CPPFLAGS)

objfiles/compress.o: mk/base_mk/compress.cpp
	$(COMPILER) -c -o objfiles/compress.o mk/base_mk/compress.cpp $(CPPFLAGS)

objfiles/crypto.o: cry/crypto.cpp
	$(COMPILER) -c -o objfiles/crypto.o cry/crypto.cpp $(CPPFLAGS)

objfiles/global_entities.o: global/global_entities.cpp
	$(COMPILER) -c -o objfiles/global_entities.o global/global_entities.cpp $(CPPFLAGS)

objfiles/pe32_i686.o: mk/pe32_i686/pe32_i686.cpp
	$(COMPILER) -c -o objfiles/pe32_i686.o mk/pe32_i686/pe32_i686.cpp $(CPPFLAGS)

objfiles/binding.o: eg/base/binding.cpp
	$(COMPILER) -c -o objfiles/binding.o eg/base/binding.cpp $(CPPFLAGS)

objfiles/part.o: eg/base/part.cpp
	$(COMPILER) -c -o objfiles/part.o eg/base/part.cpp $(CPPFLAGS)

objfiles/memory_piece.o: eg/base/memory_piece.cpp
	$(COMPILER) -c -o objfiles/memory_piece.o eg/base/memory_piece.cpp $(CPPFLAGS)

objfiles/frame.o: eg/base/frame.cpp
	$(COMPILER) -c -o objfiles/frame.o eg/base/frame.cpp $(CPPFLAGS)

objfiles/machine_state.o: eg/base/machine_state.cpp
	$(COMPILER) -c -o objfiles/machine_state.o eg/base/machine_state.cpp $(CPPFLAGS)

objfiles/form.o: eg/base/form.cpp
	$(COMPILER) -c -o objfiles/form.o eg/base/form.cpp $(CPPFLAGS)

objfiles/invariant.o: eg/base/invariant.cpp
	$(COMPILER) -c -o objfiles/invariant.o eg/base/invariant.cpp $(CPPFLAGS)

objfiles/base_eg.o: eg/base/base_eg.cpp
	$(COMPILER) -c -o objfiles/base_eg.o eg/base/base_eg.cpp $(CPPFLAGS)

objfiles/i8086.o: eg/i8086/i8086.cpp
	$(COMPILER) -c -o objfiles/i8086.o eg/i8086/i8086.cpp $(CPPFLAGS)

objfiles/i686.o: eg/i8086/i686/i686.cpp
	$(COMPILER) -c -o objfiles/i686.o eg/i8086/i686/i686.cpp $(CPPFLAGS)

$(APP): $(OBJECTS)
	$(COMPILER) -o $(APP) $(OBJECTS) $(CPPFLAGS) $(LASTFLAGS) $(LIB_DIR) $(LIBS)
