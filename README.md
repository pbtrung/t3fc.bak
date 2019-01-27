# t3fc ![License](https://dl.dropboxusercontent.com/s/cul64jahsd3cg14/license.svg?dl=0)

Dependency: [libsodium](https://github.com/jedisct1/libsodium)

Compile:

`gcc main.c argon2/*.c skein3fish/*.c hc256/*.c -O3 -o t3fc -lsodium -lpthread`