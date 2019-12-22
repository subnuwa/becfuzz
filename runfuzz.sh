#!/bin/bash


export PATH=$PATH:$PWD
# $0: runfuzz.sh itself; $1: path to output directory
# $2: fuzzing seed dir;
# $3: path to target binary;  ${@:4}: parameters running targets
# bash runfuzz.sh ../outputs/becread1 ../target-bins/untracer_bins/binutils/readelf ../target-bins/untracer_bins/binutils/seed_dir/ -a @@

OUTDIR=$1
SEEDS=$2
TARGET=$3
PARAMS=`echo ${@:4}`

NAME=`echo ${TARGET##*/}`
INSTNAME=${NAME}_inst


mkdir $OUTDIR
./BECFuzzDyninst -i $TARGET  -o  $OUTDIR/${INSTNAME} -b $OUTDIR
./becfuzz-afl -i $SEEDS -o $OUTDIR/out -t 500 -m 1G -- $OUTDIR/$INSTNAME $PARAMS