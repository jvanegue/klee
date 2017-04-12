SRC = heap8.c 
OBJ = $(SRC:.c=.bc)
CLG = clang-3.4

all: clean comp run

comp:
	$(CLG) -emit-llvm -c -g $(SRC) -I../../include

run:
	klee $(OBJ)

clean:
	rm -fr *.bc klee-last klee-out-0 *~


