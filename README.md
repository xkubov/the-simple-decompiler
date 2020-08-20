# Simple decompiler for R2

This repository contains examples used in https://engineering.avast.io/simple-r2-plugin.

## Build

To build the plugin do:

```fish
$ mkdir && cd build
$ cmake .. -DCMAKE_INSTALL_PREFIX=~/.local
$ make -j`nproc` install
```

If RetDec is not automatically found in the system specify path to the RetDec with CMake variable:
```
cmake .. -DCMAKE_PREFIX_PATH=${PATH_TO_RETDEC_ROOT}
```
