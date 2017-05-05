SRC = heap12.c 
OBJ = $(SRC:.c=.bc)
CLG = clang-3.4
EXE = test_heap12
CFLAGS=-g


all: clean comp run

comp:
	$(CLG) $(CFLAGS) -emit-llvm -c $(SRC)
	$(CLG) $(OBJ) -o $(EXE)

run:
	klee --libc=uclibc $(OBJ)
	#klee --libc=uclibc --posix-runtime $(OBJ)

clean:
	rm -fr *.bc klee-last klee-out-0 *~


