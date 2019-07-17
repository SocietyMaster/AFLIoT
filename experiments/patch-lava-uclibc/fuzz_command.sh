./runafl-lava -i inputs/base64 -o outputs/lava-base64 -d -- ./lava-targets/base64-ld -d @@
./runafl-lava -i inputs/md5sum -o outputs/lava-md5sum -d -- ./lava-targets/md5sum-ld -c @@
./runafl-lava -i inputs/uniq -o outputs/lava-uniq -d -- ./lava-targets/uniq-ld @@
./runafl-lava -i inputs/who -o outputs/lava-who -d -- ./lava-targets/who-ld @@

timeout --signal=INT 24h ./runafl-lava -i inputs/base64/ -o outputs/base64 -d -- ./targets/base64 -d @@
timeout --signal=INT 24h ./runafl-lava -i inputs/md5sum/ -o outputs/md5sum -d -- ./targets/md5sum -c @@
timeout --signal=INT 24h ./runafl-lava -i inputs/uniq/ -o outputs/uniq -d -- ./targets/uniq @@
timeout --signal=INT 24h ./runafl-lava -i inputs/who/ -o outputs/who -d -- ./targets/who @@

timeout --signal=INT 24h ./runafl-lava -i inputs/base64/ -o outputs/base64-gnu -d -- ./targets/base64-clang -d @@
timeout --signal=INT 24h ./runafl-lava -i inputs/md5sum/ -o outputs/md5sum-gnu -d -- ./targets/md5sum-clang -c @@
timeout --signal=INT 24h ./runafl-lava -i inputs/uniq/ -o outputs/uniq-gnu -d -- ./targets/uniq-clang @@
timeout --signal=INT 24h ./runafl-lava -i inputs/who/ -o outputs/who-gnu -d -- ./targets/who-clang @@