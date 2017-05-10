SRC = heap2.c 
OBJ = $(SRC:.c=.bc)
CLG = clang
CFLAGS = -I../../include

all: clean comp run

comp:
	$(CLG) -emit-llvm -c -g $(CFLAGS) $(SRC)

run:
	klee -posix-runtime -libc=uclibc -stop-after-n-tests=10 $(OBJ) --sym-args 2 2 10

clean:
	rm -fr *.bc klee-last klee-out-0 *~



