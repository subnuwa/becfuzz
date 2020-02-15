# collision free
for no-pie binaries.

## Install Dyninst

[the branch](https://github.com/mxz297/dyninst)

```
git clone https://github.com/mxz297/dyninst.git
cd dyninst
git checkout fuzzing
```
[install instructions](https://github.com/mxz297/dyninst)

## environment
```
export DYNINST_INSTALL=/path/to/dynBuildDir
export BECFUZZ_PATH=/path/to/becfuzz

export DYNINSTAPI_RT_LIB=$DYNINST_INSTALL/lib/libdyninstAPI_RT.so
export LD_LIBRARY_PATH=$DYNINST_INSTALL/lib:$BECFUZZ_PATH
export PATH=$PATH:$BECFUZZ_PATH
```

## run fuzzing

1. instrument target binaries using BECFuzzDyninst

    ./BECFuzzDyninst64 -i /path/to/target -o /path/to/instrumented/binary -b /path/to/output

2. fuzz the instrumented binary

run fuzzing

change PATH in runfuzz.sh 

```
bash runfuzz.sh output_dir target_bin seed_dir target_params
```

```
./runfuzz.sh ../outputs/test ../target-bins/untracer_bins/tcpdump/seed_dir/ ../target-bins/untracer_bins/tcpdump/tcpdump -nr @@
```
