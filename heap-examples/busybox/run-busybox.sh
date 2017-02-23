#! /bin/bash

KLEE="../../Release+Asserts/bin/klee"

KLEE_OPTIONS="--simplify-sym-indices --write-cvcs --write-cov --output-module \
--max-memory=12000 --disable-inlining --optimize --use-forked-solver \
--use-cex-cache --libc=uclibc --posix-runtime \
--allow-external-sym-calls --only-output-states-covering-new \
--max-sym-array-size=4096 --max-instruction-time=30. --max-time=6000. \
--watchdog --max-memory-inhibit=false --max-static-fork-pct=1 \
--max-static-solve-pct=1 --max-static-cpfork-pct=1 --switch-type=internal \
--randomize-fork --search=random-path --search=nurs:covnew \
--use-batching-search --batch-instructions=10000"

BUSYBOX_BC="./busybox_unstripped.bc"
APPLETS_LIST="acpid, add-shell, arping, arp, awk, base64, bzip2"
#APPLET_COMMON_OPTS="--sym-stdin 8 --sym-stdout"
APPLET_COMMON_OPTS="--sym-stdout"

if [ $# -eq 0 ]
then
  echo "[*] You should provide an applet name"
  echo "[*] Available plugins: $APPLETS_LIST"
  exit 1
fi

APPLET="$1"

case "$APPLET" in
  acpid)
    APPLET_OPTS="-c ./ -e A --sym-files 2 12"
    ;;

  add-shell)
    APPLET_OPTS="--sym-args 2 2 10"
    ;;

  arp|arping)
    APPLET_OPTS="--sym-args 6 6 10"
    ;;

  awk|base64)
    APPLET_OPTS="--sym-args 2 2 10 A --sym-files 1 10"
    ;;

  bzip2|bunzip2|bzcat)
    APPLET_OPTS="--sym-args 0 1 4 A --sym-files 1 10"
    ;;

  cal|ncal|date)
    APPLET_OPTS="--sym-args 0 2 5 --sym-args 2 2 10"
    ;;

  chat)
    APPLET_OPTS="--sym-args 2 2 10"
    ;;

  cmp)
    APPLET_OPTS="--sym-args 0 4 5 A B --sym-files 2 20"
    ;;

  cksum)
    APPLET_OPTS="A --sym-files 1 30"
    ;;

  cksum|dc)
    APPLET_OPTS="--sym-stdin 30"
    ;;

  diff|comm)
    APPLET_OPTS="--sym-args 0 2 4 A B --sym-files 2 20"
    ;;

  cut)
    APPLET_OPTS="--sym-args 0 6 10 A --sym-files 1 20"
    ;;

  egrep)
    APPLET_OPTS="--sym-args 1 1 10 A --sym-files 1 20"
    ;;

  expand)
    APPLET_OPTS="--sym-args 2 2 2 A --sym-files 1 20"
    ;;

  expr)
    APPLET_OPTS="--sym-args 0 3 10"
    ;;

  *)
    echo "[*] No such busybox applet."
    echo -e "[*] Here is the list of applets:\n $APPLETS_LIST"
    exit 1
esac

CMD="$KLEE $KLEE_OPTIONS $BUSYBOX_BC $APPLET $APPLET_OPTS $APPLET_COMMON_OPTS"
echo "Running $CMD" 
$CMD
#$KLEE $KLEE_OPTIONS $BUSYBOX_BC $APPLET $APPLET_OPTS $APPLET_COMMON_OPTS


