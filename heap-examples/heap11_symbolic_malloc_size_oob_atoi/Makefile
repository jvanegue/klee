SRC = heap11.c 
OBJ = $(SRC:.c=.bc)
CLG = clang-3.4

all: clean comp run

comp:
	$(CLG) -emit-llvm --target="x86_64-pc-linux-gnu" -c -g $(SRC)
	#llvm-dis-3.4 $(OBJ)

run:
	klee $(OBJ) 256
	#klee --libc=ucl--posix-runtime $(OBJ) --sym-args 1 1 1
	#klee --libc=uclibc --posix-runtime $(OBJ) --sym-args 1 1 10
	#klee --libc=uclibc --posix-runtime $(OBJ) 255
	#klee --libc=uclibc --posix-runtime $(OBJ) 0
	#klee --libc=uclibc --posix-runtime $(OBJ) 1
	#klee --libc=uclibc --posix-runtime $(OBJ) 256
	#klee --libc=uclibc --posix-runtime $(OBJ) 65535

clean:
	rm -fr *.bc klee-last klee-out-0 *~ *.ll


