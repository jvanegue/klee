SRC = heap3.c 
OBJ = $(SRC:.c=.bc)
CLG = clang-3.4

all: comp run

comp:
	$(CLG) -emit-llvm -c -g $(SRC)

run:
	klee -track-edges -posix-runtime -libc=uclibc $(OBJ) --sym-args 1 2 10
	#klee -posix-runtime -libc=uclibc -stop-after-n-tests=10 $(OBJ) --sym-args 1 2 10
	dot -Tpng klee-last/hklee-cfg.gv > hklee-cfg.png
	dot -Tpng klee-last/hklee-ss.gv > hklee-ss.png
	dot -Tpng klee-last/hklee-heap.gv > hklee-heap.png

clean:
	rm -fr *.bc klee-last klee-out* *.png
