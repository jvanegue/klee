SRC1 = kvwrite.c 
OBJ1 = $(SRC1:.c=.bc)
SRC2 = kvread.c
OBJ2 = $(SRC2:.c=.bc)

CLG = clang
CFLAGS = -I../../include -O0

all: clean comp run dot

comp:
	$(CLG) -emit-llvm -c -g $(CFLAGS) $(SRC1)
	$(CLG) -emit-llvm -c -g $(CFLAGS) $(SRC2)

run:
	@echo Calling kv-write example
	@klee -track-edges -posix-runtime -libc=uclibc $(OBJ1) --sym-args 2 2 3
	@echo '************************************************************'
	@echo Calling kv-read example
	@klee -track-edges -posix-runtime -libc=uclibc $(OBJ2) --sym-args 1 1 3

debug_run:
	@echo file `which klee` > klee.gdb
	@echo b Executor.cpp:3220 >> klee.gdb
	@echo b Executor.cpp:3940 >> klee.gdb
	@echo r -track-edges -posix-runtime -libc=uclibc $(OBJ2) --sym-args 1 1 3  >> klee.gdb
	@echo bt >> klee.gdb
	gdb `which klee` -x klee.gdb

debug_read:
	@echo file `which klee` > klee.gdb
	@echo b klee::Executor::terminateStateOnError >> klee.gdb
	@echo r -track-edges -posix-runtime -libc=uclibc $(OBJ2) --sym-args 1 1 3  >> klee.gdb
	@echo bt >> klee.gdb
	gdb `which klee` -x klee.gdb

dot:
	@dot -Tpng klee-last/hklee-cfg.gv > hklee-cfg.png
	@dot -Tpng klee-last/hklee-ss.gv > hklee-ss.png
	@dot -Tpng klee-last/hklee-heap.gv > hklee-heap.png

clean:
	rm -fr *.bc klee-last klee-out-0 *~ *ptests
