SRC = heap.c 
OBJ = $(SRC:.c=.bc)
CLG = clang
CFLAGS = -I../../include

all: clean comp run

comp:
	$(CLG) -emit-llvm -c -g $(CFLAGS) $(SRC)

run:
	klee $(OBJ)

clean:
	rm -fr *.bc klee-last klee-out-0 *~


