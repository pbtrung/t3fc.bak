#include <chrono>

#include "nowide/args.hpp"
#include "nowide/fstream.hpp"
#include "nowide/iostream.hpp"

#include "cppcrypto/argon2.h"
#include "cppcrypto/blake.h"
#include "cppcrypto/cbc.h"
#include "cppcrypto/ctr.h"
#include "cppcrypto/hmac.h"
#include "cppcrypto/kalyna.h"
#include "cppcrypto/skein512.h"
#include "cppcrypto/threefish.h"

#include "randombytes/randombytes.h"

const unsigned int T3F_TWEAK_LEN = 16;
const unsigned int T3F_KEY_LEN = 128;
const unsigned int T3F_BLOCK_LEN = 128;
const unsigned int T3F_CBC_IV_LEN = 128;
const unsigned int NUM_BLOCKS = 2048;
const unsigned int CHUNK_LEN = NUM_BLOCKS * T3F_BLOCK_LEN;

const unsigned int MASTER_KEY_LEN = 256;
const unsigned int SALT_LEN = 64;
const unsigned int HEADER_LEN = 6;

const unsigned int KALYNA_KEY_LEN = 64;
const unsigned int KALYNA_CBC_IV_LEN = 64;

const unsigned int HMAC_KEY_LEN = 64;
const unsigned int HMAC_HASH_LEN = 64;
const unsigned int ENC_KEY_LEN = T3F_KEY_LEN + T3F_TWEAK_LEN + T3F_CBC_IV_LEN +
                                 KALYNA_KEY_LEN + KALYNA_CBC_IV_LEN +
                                 HMAC_KEY_LEN;

const unsigned char header[HEADER_LEN] = {'t', '3', 'f', 'c', '0', '1'};

const uint32_t T = 9;
const uint32_t M = 1 << 19;
const uint32_t P = 1;

void check_fatal_err(bool cond, std::string msg) {
    if (cond) {
        nowide::cerr << "Error: " << msg << std::endl;
        exit(-2);
    }
}

bool file_exists(const char *filename) {
    nowide::ifstream ifile(filename);
    return (bool)ifile;
}

size_t get_file_size(const char *filename) {
    nowide::ifstream f;
    f.open(filename, std::ios_base::binary | std::ios_base::in);
    check_fatal_err(!f.good() || f.eof() || !f.is_open(),
                    "cannot get file size.");
    f.seekg(0, std::ios_base::beg);
    nowide::ifstream::pos_type begin_pos = f.tellg();
    f.seekg(0, std::ios_base::end);
    return static_cast<size_t>(f.tellg() - begin_pos);
}

void get_master_key(const char *path, unsigned char *master_key) {
    size_t file_size = get_file_size(path);
    check_fatal_err(file_size != MASTER_KEY_LEN,
                    "key file must have exactly 256 bytes.");
    nowide::ifstream in_file(path, std::ios::binary);
    in_file.read((char *)master_key, file_size);
    check_fatal_err(!in_file || in_file.gcount() != MASTER_KEY_LEN,
                    "cannot read master key from file.");
    in_file.close();
}

void encrypt(nowide::ifstream &in_file, nowide::ofstream &out_file,
             unsigned char *master_key);
void decrypt(nowide::ifstream &in_file, nowide::ofstream &out_file,
             unsigned char *master_key);
void make_key(unsigned char *master_key, unsigned char *enc_key,
              unsigned char *salt);

int main(int argc, char **argv) {

    unsigned char master_key[MASTER_KEY_LEN];
    try {
        nowide::args args(argc, argv);
        if (argc == 3 && strcmp(argv[1], "-kf") == 0) {
            randombytes(master_key, MASTER_KEY_LEN);
            nowide::ofstream key_file(argv[2], std::ios::binary);
            key_file.write((char *)master_key, MASTER_KEY_LEN);
            key_file.close();
            check_fatal_err(!key_file, "cannot write master key to file.");

        } else if (argc == 8 &&
                   (strcmp(argv[1], "-e") == 0 || strcmp(argv[1], "-d") == 0) &&
                   strcmp(argv[2], "-k") == 0 && strcmp(argv[4], "-i") == 0 &&
                   strcmp(argv[6], "-o") == 0) {

            if (file_exists(argv[7])) {
                std::string yn;
                do {
                    nowide::cout
                        << "File exists. Do you want to overwrite? (y/n) "
                        << std::flush;
                    nowide::cin >> yn;
                } while (yn != "n" && yn != "N" && yn != "y" && yn != "Y");
                if (yn == "n" || yn == "N") {
                    nowide::cout << "Please choose a different output file."
                                 << std::endl;
                    return EXIT_SUCCESS;
                }
            }

            get_master_key(argv[3], master_key);
            nowide::ifstream in_file(argv[5], std::ios::binary);
            nowide::ofstream out_file(argv[7], std::ios::binary);
            if (strcmp(argv[1], "-e") == 0) {
                encrypt(in_file, out_file, master_key);
            } else if (strcmp(argv[1], "-d") == 0) {
                decrypt(in_file, out_file, master_key);
            }
            in_file.close();
            out_file.close();
            check_fatal_err(!out_file, "cannot write to file.");

        } else {
            check_fatal_err(true, "unknown options.");
        }
    } catch (std::exception const &ex) {
        nowide::cerr << "caught: " << ex.what() << std::endl;
        exit(-1);
    }
}

void make_key(unsigned char *master_key, unsigned char *enc_key,
              unsigned char *salt) {
    std::chrono::high_resolution_clock::time_point s =
        std::chrono::high_resolution_clock::now();
    cppcrypto::argon2id((const char *)master_key, MASTER_KEY_LEN, salt,
                        SALT_LEN, P, M, T, enc_key, ENC_KEY_LEN);
    std::chrono::high_resolution_clock::time_point e =
        std::chrono::high_resolution_clock::now();
    auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(e - s).count();
    nowide::cout << "argon2id " << duration << "ms" << std::endl;
}

void encrypt(nowide::ifstream &in_file, nowide::ofstream &out_file,
             unsigned char *master_key) {

    out_file.write((char *)header, HEADER_LEN);
    unsigned char salt[SALT_LEN];
    randombytes(salt, SALT_LEN);
    out_file.write((char *)salt, SALT_LEN);

    unsigned char enc_key[ENC_KEY_LEN];
    make_key(master_key, enc_key, salt);
    
    std::chrono::high_resolution_clock::time_point s =
        std::chrono::high_resolution_clock::now();
    cppcrypto::threefish1024_1024 t3f;
    t3f.init((const unsigned char *)enc_key,
             cppcrypto::block_cipher::encryption);
    t3f.set_tweak((const unsigned char *)&enc_key[T3F_KEY_LEN]);
    cppcrypto::ctr t3f_ctr(t3f);
    t3f_ctr.init((const unsigned char *)enc_key, T3F_KEY_LEN,
                 (const unsigned char *)&enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN],
                 T3F_CBC_IV_LEN);
    cppcrypto::kalyna512_512 kl;
    cppcrypto::ctr kl_ctr(kl);
    kl_ctr.init(
        (const unsigned char *)&enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN + T3F_CBC_IV_LEN],
        KALYNA_KEY_LEN,
        (const unsigned char *)&enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN +
                                        T3F_CBC_IV_LEN + KALYNA_KEY_LEN], KALYNA_CBC_IV_LEN);
    cppcrypto::hmac hmac(cppcrypto::skein512(512),
                         &enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN + T3F_CBC_IV_LEN +
                                  KALYNA_KEY_LEN + KALYNA_CBC_IV_LEN],
                         HMAC_KEY_LEN);
                         
    hmac.update(header, HEADER_LEN);
    hmac.update(salt, SALT_LEN);
    
    std::vector<unsigned char> chunk(CHUNK_LEN);
    size_t chunk_len = 0;
    while (in_file) {
        in_file.read((char *)chunk.data(), CHUNK_LEN);
        chunk_len = in_file.gcount();
        if (chunk_len == 0) {
            break;
        }
        t3f_ctr.encrypt(chunk.data(), chunk_len, chunk.data());
        kl_ctr.encrypt(chunk.data(), chunk_len, chunk.data());
        hmac.update(chunk.data(), chunk_len);
        out_file.write((char *)chunk.data(), chunk_len);
    }

    unsigned char hmac_hash[HMAC_HASH_LEN];
    hmac.final(hmac_hash);
    out_file.write((char *)hmac_hash, HMAC_HASH_LEN);
    
    std::chrono::high_resolution_clock::time_point e =
        std::chrono::high_resolution_clock::now();
    auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(e - s).count();
    nowide::cout << "encrypt  " << duration << "ms" << std::endl;
}

void decrypt(nowide::ifstream &in_file, nowide::ofstream &out_file,
             unsigned char *master_key) {
                 
    unsigned char in_header[HEADER_LEN];
    in_file.read((char *)in_header, HEADER_LEN);
    check_fatal_err(!in_file || in_file.gcount() != HEADER_LEN,
                    "cannot read header.");
    check_fatal_err(memcmp(in_header, header, HEADER_LEN) != 0,
                    "wrong header.");
    unsigned char salt[SALT_LEN];
    in_file.read((char *)salt, SALT_LEN);
    check_fatal_err(!in_file || in_file.gcount() != SALT_LEN,
                    "cannot read salt.");
                    
    unsigned char enc_key[ENC_KEY_LEN];
    make_key(master_key, enc_key, salt);
    
    std::chrono::high_resolution_clock::time_point s =
        std::chrono::high_resolution_clock::now();
    cppcrypto::threefish1024_1024 t3f;
    t3f.init((const unsigned char *)enc_key,
             cppcrypto::block_cipher::decryption);
    t3f.set_tweak((const unsigned char *)&enc_key[T3F_KEY_LEN]);
    cppcrypto::ctr t3f_ctr(t3f);
    t3f_ctr.init((const unsigned char *)enc_key, T3F_KEY_LEN,
                 (const unsigned char *)&enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN],
                 T3F_CBC_IV_LEN);
    cppcrypto::kalyna512_512 kl;
    cppcrypto::ctr kl_ctr(kl);
    kl_ctr.init(
        (const unsigned char *)&enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN + T3F_CBC_IV_LEN],
        KALYNA_KEY_LEN,
        (const unsigned char *)&enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN +
                                        T3F_CBC_IV_LEN + KALYNA_KEY_LEN], KALYNA_CBC_IV_LEN);
    cppcrypto::hmac hmac(cppcrypto::skein512(512),
                         &enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN + T3F_CBC_IV_LEN +
                                  KALYNA_KEY_LEN + KALYNA_CBC_IV_LEN],
                         HMAC_KEY_LEN);
                         
    hmac.update(header, HEADER_LEN);
    hmac.update(salt, SALT_LEN);
    
    std::vector<unsigned char> chunk(CHUNK_LEN);
    size_t chunk_len = 0;
    while (in_file) {
        in_file.read((char *)chunk.data(), CHUNK_LEN);
        chunk_len = in_file.gcount();
        if (chunk_len == 0) {
            break;
        } else if (chunk_len < CHUNK_LEN && chunk_len > HMAC_HASH_LEN) {
            chunk_len -= HMAC_HASH_LEN;
        }
        hmac.update(chunk.data(), chunk_len);
        kl_ctr.decrypt(chunk.data(), chunk_len, chunk.data());
        t3f_ctr.decrypt(chunk.data(), chunk_len, chunk.data());
        out_file.write((char *)chunk.data(), chunk_len);
    }
    
    unsigned char hmac_hash[HMAC_HASH_LEN];
    hmac.final(hmac_hash);
    
    std::chrono::high_resolution_clock::time_point e =
        std::chrono::high_resolution_clock::now();
    auto duration =
        std::chrono::duration_cast<std::chrono::milliseconds>(e - s).count();
    nowide::cout << "decrypt  " << duration << "ms" << std::endl;
}