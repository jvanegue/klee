#! /bin/bash

VKLEE="../../../klee/Release+Asserts/bin/klee"
HKLEE="../../Release+Asserts/bin/klee"

KLEE_OPTIONS="--simplify-sym-indices --write-cvcs --write-cov --output-module \
--max-memory=12000 --disable-inlining --optimize --use-forked-solver \
--use-cex-cache --libc=uclibc --posix-runtime \
--allow-external-sym-calls --only-output-states-covering-new \
--max-sym-array-size=4096 --max-instruction-time=30. --max-time=10 \
--watchdog --max-memory-inhibit=false --max-static-fork-pct=1 \
--max-static-solve-pct=1 --max-static-cpfork-pct=1 --switch-type=internal \
--use-batching-search --batch-instructions=10000"

HKLEE_OPTIONS="--symbolic-stubs=1"

TCPDUMP="./tcpdump.bc"

TARGET=$TCPDUMP

COMMON_OPTS="--sym-stdout --sym-args 0 2 10 A --sym-files 1 100"

SEARCH_OPT_RP="-search=random-path"
SEARCH_OPT_CN="-search=nurs:covnew"
SEARCH_OPT_MD="-search=nurs:md2u"
SEARCH_OPT_DEPTH="-search=nurs:depth"
SEARCH_OPT_ICNT="-search=nurs:icnt"
SEARCH_OPT_CPICNT="-search=nurs:cpicnt"
SEARCH_OPT_QC="-search=nurs:qc"

#CMD="$KLEE $KLEE_OPTIONS $SEARCH $TARGET $COMMON_OPTS"

CMD1="$KLEE $KLEE_OPTIONS $SEARCH_OPT_RP $TARGET $COMMON_OPTS"
CMD2="$KLEE $KLEE_OPTIONS $SEARCH_OPT_CN $TARGET $COMMON_OPTS"
CMD3="$KLEE $KLEE_OPTIONS $SEARCH_OPT_MD $TARGET $COMMON_OPTS"
CMD4="$KLEE $KLEE_OPTIONS $SEARCH_OPT_DEPTH $TARGET $COMMON_OPTS"
CMD5="$KLEE $KLEE_OPTIONS $SEARCH_OPT_ICNT $TARGET $COMMON_OPTS"
CMD6="$KLEE $KLEE_OPTIONS $SEARCH_OPT_CPICNT $TARGET $COMMON_OPTS"
CMD7="$KLEE $KLEE_OPTIONS $SEARCH_OPT_QC $TARGET $COMMON_OPTS"


for i in klee hklee; do

    TESTDIR=$i-test
    rm -fr $TESTDIR
    mkdir $TESTDIR

    if [ "$i" == "klee" ]; then
	KLEE=$VKLEE
    else
	KLEE=$HKLEE
    fi

    echo CHOSEN KLEE = $KLEE
    echo TEST DIR = $TESTDIR
    
    for j in random-path nurs:covnew nurs:md2u nurs:depth nurs:icnt nurs:cpicnt nurs:qc; do 

	CMD="$KLEE $KLEE_OPTIONS -search=$j $TARGET $COMMON_OPTS"
	echo "Running $CMD"
	$CMD
	mkdir $TESTDIR/$j
	mv klee-out* ./$TESTDIR/$j

    done

done


#echo "Running $CMD2"
#$CMD2
#echo "Running $CMD3"
#$CMD3
#echo "Running $CMD4"
#$CMD4
#echo "Running $CMD5"
#$CMD5
#echo "Running $CMD6"
#$CMD6
#echo "Running $CMD7"
#$CMD7
