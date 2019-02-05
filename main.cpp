#include <string>
#include <iostream>

#include "cppcrypto/skein512.h"

int main(int argc, char **argv) {
    cppcrypto::skein512 skein512(512);
    unsigned char result[64];
    skein512.hash_string("The quick brown fox jumps over the lazy dog", result);
    for (int i = 0; i < 64; ++i)
        std::cout << std::hex << (int)result[i];
    std::cout << std::endl;
    return EXIT_SUCCESS;
}