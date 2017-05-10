SRC = heap14.c 
OBJ = $(SRC:.c=.bc)
CLG = clang-3.4

all: clean comp run

comp:
	$(CLG) -emit-llvm --target="x86_64-pc-linux-gnu" -c -g $(SRC)

run:
	klee $(OBJ) -stop-after-n-tests=1 --sym-args 1 1 1

clean:
	rm -fr *.bc klee-last klee-out-0 *~



