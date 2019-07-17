# avoid accidental execute
exit 0

# compile afl-llvm
export AFL_NO_X86=1; gmake && gmake -C llvm_mode && gmake install

# compile coreutils-who using clang with afl-clang cflags
make clean; FORCE_UNSAFE_CONFIGURE=1 ./configure CC=clang CFLAGS="-Qunused-arguments -g -O3 -funroll-loops"; FORCE_UNSAFE_CONFIGURE=1 make src/who

# compile coreutils-who using afl-clang-fast
make clean; FORCE_UNSAFE_CONFIGURE=1 ./configure CC=afl-clang-fast; FORCE_UNSAFE_CONFIGURE=1 make src/who

# compile coreutils-who using clang with afl-clang cflags and coverage
make clean; FORCE_UNSAFE_CONFIGURE=1 ./configure CC=clang CFLAGS="-Qunused-arguments -g -O3 -funroll-loops -fprofile-arcs -ftest-coverage"; FORCE_UNSAFE_CONFIGURE=1 make src/who

# afl fuzz command line
afl-fuzz -d -t 500 -i input -o output ./who @@

# afl run coverage
/root/afl/afl-cov/afl-cov -d /root/afl/afl-cov/afl-clang-fast --coverage-cmd "/root/source/who-clang-gcov/coreutils-8.24-lava-safe/src/who AFL_FILE" --code-dir "/root/source/who-clang-gcov/coreutils-8.24-lava-safe/src/" --enable-branch-coverage --overwrite --lcov-path /root/afl/afl-cov/lcov --verbose
