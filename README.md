# AFLIoT Setup
## Instrumentation
We tested **instrumentation phase** on Windows 10 Pro 64-bit Version 1909.

Instrumentation requires [IDA Pro 7.0](https://www.hex-rays.com/products/ida/). Please install it at first.

You could setup the instrumentation enviroment by the following commands:

``` shell
git clone https://github.com/SocietyMaster/AFLIoT.git AFLIoT
cd AFLIoT
git clone https://github.com/SocietyMaster/ELFPatcher.git ELFPatcher
git clone https://github.com/SocietyMaster/keystone.git keystone
cd keystone/binding/python
python setup.py install
```

Please make sure:
1. The variable `ELFPATCHER_PATH` in line 324 of file `cov-instrument/afl-instrument.py`is the path of [ELFPatcher](https://github.com/SocietyMaster/ELFPatcher.git) repository you just cloned.
    ```python
    def do_instrument(...): # line 323
        ELFPATCHER_PATH = os.path.abspath(os.path.join("..", "ELFPatcher"))
        sys.path.append(ELFPATCHER_PATH)
    ```
2. Keystone is installed to IDA python.

Then you can instrument the binary file by following commands:
```
Usage: afl-instrument.py -f elfpath [-o output] [-i idapath] [-d mode] [-s] [-p pass] [-h]

-f      target elf file path
-o      patched output file path, default is elfpath-patch
-i      ida pro executable path, default is hardcoded
-d      target is daemon, using 'desock' or 'client' mode
-s      single thread mode without TLS
-p      only instrument code whose address <= 0x`pass`
-h      show this
```

For common binary program, you should identify the path of IDA by `-i`. We only tested IDA Pro 7.0.

For example:
```
python afl-instrument.py -f elfpath -o elfpath-patch -i c:/ida/ida.exe
```

For daemon program, AFLIoT leveraging the desock hooking to forwarding the inputs. Please add `-d desock` to instrument the daemon binary.
```
python afl-instrument.py -f elfpath -o elfpath-desock -d desock -i c:/ida/ida.exe
```

## Fuzzing
We directly using the [American Fuzzy Lop](https://lcamtuf.coredump.cx/afl/) to fuzz the binary we instrumented before. The version of AFL we tested is 2.52b.

We already provided an copy (in `orginal-source/`) of AFL 2.52b in this repository. You can also download it from offical website.

Compile the AFL by following commmand:
``` shell
    export CC=arm-linux-gcc
    export AFL_NO_X86=1
    make
```

Then copy the compiled AFL binaries to target devices.

Then you should update the fuzzing script based on the following template:
``` bash
# libraries path
export LD_LIBRARY_PATH=path_to_libraries

# patched timeout, will exit fuzz-instance when timeout
export AFL_DAEMON_TIMEOUT=1000000

# client mode, timeout for forwarding to the daemon
export AFL_FORWARD_TIMEOUT=1000

# enable debug for desock mode
# export DESOCK_DEBUG=1

# desock mode which port to capture
export DESOCK_PORT=784

# stupid check for AFL_SHM_ENV string, but it is in the libaflinit.so
export AFL_SKIP_BIN_CHECK=1

# afl catch up
export AFL_NO_AFFINITY=1

# afl setup
echo core >/proc/sys/kernel/core_pattern
./afl-fuzz $@
```

And place the scripts in the same directory of AFL binaries.

Then you can test the common binaries by the following command, for instance:
```
./runafl -i input -o output [-d] -- ./targets/target-patch program_parameters（using `@@` if you want to input a file）
```

To test daemon program, you should make sure the daemon is already run in the background.
```shell
# configure the DESOCK target port
export DESOCK_PORT=784			# 指定目标端口
# fuzz
./runafl -i input -o output [-d] -- ./targets/target-desock program_parameters
```
