SRC = heap10.c 
OBJ = $(SRC:.c=.bc)
CLG = clang-3.4

all: clean comp run

comp:
	$(CLG) -emit-llvm --target="x86_64-pc-linux-gnu" -c -g $(SRC)


run:
	klee -max-time=10 -max-instruction-time=10 -max-solver-time=10 -track-edges -posix-runtime -libc=uclibc $(OBJ) --sym-args 1 2 10
	#klee -posix-runtime -libc=uclibc -stop-after-n-tests=10 $(OBJ) --sym-args 1 2 10
	dot -Tpng klee-out-0/hklee-cfg.gv > hklee-cfg.png
	dot -Tpng klee-out-0/hklee-ss.gv > hklee-ss.png
	dot -Tpng klee-out-0/hklee-heap.gv > hklee-heap.png

clean:
	rm -fr *.bc klee-last klee-out* *.png
