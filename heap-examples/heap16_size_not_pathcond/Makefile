SRC = heap16.c 
OBJ = $(SRC:.c=.bc)
CLG = clang
CFLAGS = -I../../include -O0

all: clean comp run

comp:
	$(CLG) -emit-llvm -c -g $(CFLAGS) $(SRC)

run:
	klee -symbolic-stubs=1 -posix-runtime -libc=uclibc $(OBJ) --sym-args 1 1 5

clean:
	rm -fr *.bc klee-last klee-out-0 *~
