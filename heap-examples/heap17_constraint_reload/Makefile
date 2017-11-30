SRC1 = kvwrite.c 
OBJ1 = $(SRC1:.c=.bc)
SRC2 = kvread.c
OBJ2 = $(SRC2:.c=.bc)

CLG = clang
CFLAGS = -I../../include -O0

all: clean comp run

comp:
	$(CLG) -emit-llvm -c -g $(CFLAGS) $(SRC1)
	$(CLG) -emit-llvm -c -g $(CFLAGS) $(SRC2)

run:
	echo Calling kv-write example
	klee -posix-runtime -libc=uclibc $(OBJ1) --sym-args 2 2 3
	echo Calling kv-read example
	klee -posix-runtime -libc=uclibc $(OBJ2) --sym-args 1 1 3

clean:
	rm -fr *.bc klee-last klee-out-0 *~



