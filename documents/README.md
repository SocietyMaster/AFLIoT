## 相关文件路径

+ fuzz相关的so以及主程序在xiaomi的`/userdisk/fuzz`
+ 各种源代码都在frog的`/home/zhumengfan/fuzzing/cov-instrument`
+ afl-instrument.py也在frog的`/home/zhumengfan/fuzzing/cov-instrument`

## Patch

需要使用[elf-patcher](https://github.com/Himyth/elf-patcher)库，pull完之后修改afl-instrument.py里的路径到repo：

```python
def do_instrument(target, output, bbs, disable_tls, daemon_mode):
    sys.path.append('D:\\MyWorkStation\\PyCharm\\ELFPatcher')
```

需要使用修改过的[keystone](https://github.com/Himyth/keystone)，对于windows和linux，可以直接安装编译完的链接库，否则需要编译：

```
cd bindings/python
python setup.py install
```

运行参数：

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

对于普通程序，指定ida路径，IDA只在6.95/7.0上测试过，其他版本可能会有问题：

```
python afl-instrument.py -f elfpath -o elfpath-patch -i c:/ida/ida.exe
```

对于daemon程序，使用desock hook，或者使用client forward：

```
python afl-instrument.py -f elfpath -o elfpath-desock -d desock
python afl-instrument.py -f elfpath -o elfpath-client -d client
```

对于比较大的程序，只希望插桩某一部分（<=0x12345）：

```
python afl-instrument.py -f elfpath -o elfpath-patch -p 12345
```

## 环境变量

```
root@XiaoQiang:/userdisk/fuzz# cat runafl 
#!/bin/sh

# libraries path
export LD_LIBRARY_PATH=/userdisk/fuzz/libraries

# patched timeout, will exit fuzz-instance when timeout
export AFL_DAEMON_TIMEOUT=1000000

# client mode, timeout for forwarding to the daemon
export AFL_FORWARD_TIMEOUT=1000

# enable debug for client mode
# export AFL_DAEMON_DEBUG=1

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

## 测试普通程序

```
./runafl -i input -o output [-d] -- ./targets/target-patch 程序的选项（输入文件用@@）
```

## 测试daemon程序

使用client

```
# 先启动server
./daemon-server 127.0.0.1 port

# 再启动afl，AFLFILE_PREFIX@@AFLFILE_SUFFIX这一段直接接在某个选项之后即可
./runafl -i input -o output [-d] -- ./targets/target-client -some_optionAFLFILE_PREFIX@@AFLFILE_SUFFIX ...

# 可用环境变量
export AFL_FORWARD_TIMEOUT=1000		# 发送文件超时的毫秒数，用于daemon-server
export AFL_DAEMON_TIMEOUT=1000000	# afl-fuzz运行单个实例超时的微秒数，用于afl-fuzz
export AFL_DAEMON_DEBUG=aaa			# 启用daemon-server的debug输出
```

使用desock

```
# 需要 export DESOCK_PORT=784 指定目标端口
./runafl -i input -o output [-d] -- ./targets/target-desock 程序的选项

# 可用环境变量
export DESOCK_DEBUG=aaa			# 启用desock的debug输出
export DESOCK_PORT=784			# 指定目标端口
```

