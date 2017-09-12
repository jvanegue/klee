#! /bin/bash

VKLEE="../../../klee/Release+Asserts/bin/klee"
HKLEE="../../Release+Asserts/bin/klee"

KLEE_OPTIONS="--simplify-sym-indices --write-cvcs --write-cov --output-module \
--max-memory=12000 --disable-inlining --optimize --use-forked-solver \
--use-cex-cache --libc=uclibc --posix-runtime \
--allow-external-sym-calls --only-output-states-covering-new \
--max-sym-array-size=4096 --max-instruction-time=30. --max-time=172000 \
--watchdog --max-memory-inhibit=false --max-static-fork-pct=1 \
--max-static-solve-pct=1 --max-static-cpfork-pct=1 --switch-type=internal"
#--use-batching-search --batch-instructions=10000"

HKLEE_OPTIONS="--symbolic-stubs=1"

#COMMON_OPTS="--sym-stdout --sym-args 0 2 10 A --sym-files 1 100"
COMMON_OPTS="-vvv -e -r A --sym-files 1 100"

TCPDUMP="./tcpdump.bc"
TARGET=$TCPDUMP

for i in hklee; do

    TESTDIR=$i-test
    rm -fr $TESTDIR
    mkdir $TESTDIR

    if [ "$i" == "klee" ]; then
	KLEE=$VKLEE
    else
	KLEE=$HKLEE
    fi
    
    for j in nurs:icnt; do 

	echo CHOSEN KLEE = $KLEE
	echo TEST DIR = $TESTDIR
	
	CMD="$KLEE $KLEE_OPTIONS -search=$j $TARGET $COMMON_OPTS"
	echo "Running $CMD"
	$CMD > klee-stdout.txt 2> klee-stderr.txt
	mkdir $TESTDIR/$j
	mv klee-out* ./$TESTDIR/$j
	mv klee-stdout.txt ./$TESTDIR/$j
	mv klee-stderr.txt ./$TESTDIR/$j

    done

done
