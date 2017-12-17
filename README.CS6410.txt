To build my version of KLEE ("HKLEE"), you will need:

- LLVM 3.4 with clang and clang++
- STP constraint solver
- klee-uclibc library

First do the following:

$ ./configure --with-stp=/home/jvanegue/stp --enable-posix-runtime --with-llvmcc=/home/jvanegue/llvm-3.4/llvm-3.4-build/Release+Asserts/bin/clang --with-llvmcxx=/home/jvanegue/llvm-3.4/llvm-3.4-build/Release+Asserts/bin/clang++ --with-uclibc=/home/jvanegue/klee-uclibc

(replace the paths for stp, clang and clang++ by yours)

Then:

$ make -j10


I typically build llvm from sources however the stock llvm 3.4 on ubuntu should be enough.

Then set your environment:

export PATH=~/hklee/Release+Asserts/bin/:$PATH
export LD_LIBRARY_PATH=~/hklee/Release+Asserts/lib/:$LD_LIBRARY_PATH

To execute the demo:

$ cd heap-examples/heap17_constraint_reload
$ make

You should see HKLEE execute on two test cases:

- kvwrite: will export constraints in kvread-ptests directory
- kvread: will import constraints from ptests files

The evaluation section of my report documents this demo.

Julien
