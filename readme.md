# Overview
BECFuzz aims to fuzz binaries efficiently. The current version is for non-PIE binaries.

## Install Dyninst
We use Dyninst to instrument target binaries. So firstly, install Dyninst [the branch](https://github.com/mxz297/dyninst).

```
git clone https://github.com/mxz297/dyninst.git
cd dyninst
git checkout fuzzing
```
Then, follow the instructions on [install instructions](https://github.com/mxz297/dyninst) to install Dyninst.

## Set up ENVs
```
export DYNINST_INSTALL=/path/to/dyninst/build/dir
export BECFUZZ_PATH=/path/to/becfuzz

export DYNINSTAPI_RT_LIB=$DYNINST_INSTALL/lib/libdyninstAPI_RT.so
export LD_LIBRARY_PATH=$DYNINST_INSTALL/lib:$BECFUZZ_PATH
export PATH=$PATH:$BECFUZZ_PATH
```
## Install BECFuzz
Enter the folder becfuzz.
Change DYN_ROOT in makefile accordingly. Then
```
make clean && make all
```

# Instrument binary and run fuzzing
${VERSION}: 64, 128, or 256

$TARGET: Path to target binary

${OUTDIR}: Output folder for instrumented binary and results of fuzzing

${INSTNAME}: The name of instrumented binary

$SEEDS: Path to the folder including initial seeds

$TIMEOUT: Timeout for each execution

$PARAMS: Parameters for running target binary

## Instrument target binaries
Instrument target binaries using BECFuzzDyninst

```
mkdir $OUTDIR
./BECFuzzDyninst${VERSION} -i $TARGET  -o  ${OUTDIR}/${INSTNAME} -b $OUTDIR
```

## Run fuzzing

Fuzz with the instrumented binary.

```
./becfuzz-afl${VERSION} -i $SEEDS -o ${OUTDIR}/out -t $TIMEOUT -m 1G -- ${OUTDIR}/${INSTNAME} $PARAMS
```
