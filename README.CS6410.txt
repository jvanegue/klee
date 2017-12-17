To build my fork of KLEE ("HKLEE"), you will need:

- LLVM 3.4 with clang and clang++
- STP constraint solver
- klee-uclibc library

LLVM 3.4 can be found on many linux distros, and you can also build it from sources. I have had
good luck with following instructions:

http://linuxdeveloper.blogspot.com/2014/06/building-llvm-342-from-source.html

* Here are the very good external instructions to build STP:

http://klee.github.io/build-stp/

* klee-uclibc build instructions are:

$ git clone https://github.com/klee/klee-uclibc.git
$ cd klee-uclibc
$ ./configure --make-llvm-lib
$ make -j2

* Build hklee, my KLEE fork with symbolic heap and constraint transfer functions:

git clone https://github.com/jvanegue/klee

The configure line I personally use is:

$ ./configure --with-stp=/home/jvanegue/stp --enable-posix-runtime --with-llvmcc=/home/jvanegue/llvm-3.4/llvm-3.4-build/Release+Asserts/bin/clang --with-llvmcxx=/home/jvanegue/llvm-3.4/llvm-3.4-build/Release+Asserts/bin/clang++ --with-uclibc=/home/jvanegue/klee-uclibc

(replace the paths for stp, clang and clang++ by yours)

To build HKLEE:

$ make -j10

I typically build llvm from sources however the stock llvm 3.4 on ubuntu should be enough if your machine has all the package dependences installed.

To test HKLEE, first set your environment:

export PATH=~/hklee/Release+Asserts/bin/:$PATH
export LD_LIBRARY_PATH=~/hklee/Release+Asserts/lib/:$LD_LIBRARY_PATH

To execute the CS6410 demo:

$ cd heap-examples/heap17_constraint_reload
$ make

You should see HKLEE execute on two test cases:

- kvwrite: will export constraints in kvread-ptests directory
- kvread: will import constraints from ptests files

Please refer to the evaluation section of my report for further details.

Julien
