SRC = heap.c 
OBJ = $(SRC:.c=.bc)
CLG = clang
CFLAGS = -I../../include #-fsanitize=address
#LDFLAGS=-fsanitize=address

all: clean comp run

comp:
	$(CLG) -emit-llvm -c -g $(CFLAGS) $(SRC)

run:
	klee $(OBJ) -stop-after-n-tests=1 --sym-args 1 1 1

clean:
	rm -fr *.bc klee-last klee-out-0 *~



