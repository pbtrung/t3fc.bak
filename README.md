# t3fc ![License](https://dl.dropboxusercontent.com/s/cul64jahsd3cg14/license.svg?dl=0)

Dependency: [libsodium](https://github.com/jedisct1/libsodium)

Compile: `gcc main.c argon2/*.c skein3fish/*.c -O3 -march=native -o t3fc -lpthread -lsodium`