SRC1 = kvwrite.c 
OBJ1 = $(SRC1:.c=.bc)
SRC2 = kvread.c
OBJ2 = $(SRC2:.c=.bc)

CLG = clang
CFLAGS = -I../../include -O0

all: clean comp run

comp:
	$(CLG) -emit-llvm -c -g $(CFLAGS) $(SRC1)
	$(CLG) -emit-llvm -c -g $(CFLAGS) $(SRC2)

run:
	@echo Calling kv-write example
	@klee -track-edges -posix-runtime -libc=uclibc $(OBJ1) --sym-args 2 2 3

disabled: @echo Calling kv-read example
	@klee -track-edges -posix-runtime -libc=uclibc $(OBJ2) --sym-args 1 1 3
	@dot -Tpng klee-out-0/hklee-cfg.gv > hklee-cfg.png
	@dot -Tpng klee-out-0/hklee-ss.gv > hklee-ss.png
	@dot -Tpng klee-out-0/hklee-heap.gv > hklee-heap.png


clean:
	rm -fr *.bc klee-last klee-out-0 *~



