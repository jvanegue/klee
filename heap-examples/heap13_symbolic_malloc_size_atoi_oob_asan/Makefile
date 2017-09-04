SRC = heap13.c 
OBJ = $(SRC:.c=.bc)
CLG = clang-3.4
EXE = heap13
CFLAGS = -fsanitize=address -fno-omit-frame-pointer
LDFLAGS = -fsanitize=address
LD    = clang-3.4

all: clean comp run

comp:
	$(CLG) -emit-llvm -c -g $(SRC)
	$(CLG) -g $(CFLAGS) $(SRC) -o $(EXE)

run:
	klee -track-edges -posix-runtime -libc=uclibc $(OBJ) --sym-args 1 2 10
	#klee -posix-runtime -libc=uclibc -stop-after-n-tests=10 $(OBJ) --sym-args 1 2 10
	dot -Tpng klee-out-0/hklee-cfg.gv > hklee-cfg.png
	dot -Tpng klee-out-0/hklee-ss.gv > hklee-ss.png
	dot -Tpng klee-out-0/hklee-heap.gv > hklee-heap.png

clean:
	rm -fr *.bc klee-last klee-out* *.png
