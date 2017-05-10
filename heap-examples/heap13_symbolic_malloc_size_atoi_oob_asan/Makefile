SRC = heap13.c 
OBJ = $(SRC:.c=.bc)
CLG = clang-3.4
EXE = test13

all: clean comp run

comp:
	$(CLG) -fsanitize=address -fno-omit-frame-pointer -emit-llvm --target="x86_64-pc-linux-gnu" -g $(SRC) -c
	#$(CLG) $(OBJ) -fsanitize=address -Wl,-shared-libasan -o $(EXE)

run:
	klee --libc=uclibc --posix-runtime $(OBJ) --sym-args 1 5 5 -stop-after-n-tests=1 

clean:
	rm -fr *.bc klee-last klee-out-0 *~ *.ll



