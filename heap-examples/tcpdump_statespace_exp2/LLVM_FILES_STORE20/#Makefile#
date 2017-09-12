TARGET_TCPDUMP = tcpdump.bc
TARGET_OPENSSL = openssl-bin.bc

all: tcpdump openssl

tcpdump:
	klee -posix-runtime -libc=uclibc $(TARGET_TCPDUMP) --sym-args 1 2 10
	cp klee-out-0/heapdebug.txt .

openssl:
	klee -posix-runtime -libc=uclibc $(TARGET_OPENSSL) --sym-args 1 2 10
	cp klee-out-0/heapdebug.txt .
