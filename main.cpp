#include <cstring>
#include <filesystem>
#include <string>
#include <vector>

#include <cryptopp/hc256.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha3.h>
#include <cryptopp/threefish.h>

#include "argon2/argon2.h"
#include "nowide/args.hpp"
#include "nowide/fstream.hpp"
#include "nowide/iostream.hpp"

namespace fs = std::filesystem;

const unsigned int T3F_BLOCK_LEN = 128;
const unsigned int NUM_BLOCKS = 1024;
const unsigned int CHUNK_LEN = NUM_BLOCKS * T3F_BLOCK_LEN;
const unsigned int SALT_LEN = 32;
const unsigned int HEADER_LEN = 6;
const unsigned int MASTER_KEY_LEN = 256;
const unsigned int T3F_KEY_LEN = 128;
const unsigned int HC256_KEY_LEN = 32;
const unsigned int HC256_IV_LEN = 32;
const unsigned int T3F_TWEAK_LEN = 16;
const unsigned int HMAC_KEY_LEN = 64;
const unsigned int HMAC_HASH_LEN = 64;
const unsigned int ENC_KEY_LEN =
    T3F_KEY_LEN + T3F_TWEAK_LEN + HC256_KEY_LEN + HC256_IV_LEN + HMAC_KEY_LEN;
const unsigned char header[HEADER_LEN] = {'t', '3', 'f', 'c', '0', '1'};
const uint32_t T = 8;
const uint32_t M = 1 << 18;
const uint32_t P = 1;

void check_fatal_err(bool cond, std::string msg) {
    if (cond) {
        nowide::cerr << "Error: " << msg << std::endl;
        exit(-3);
    }
}

size_t get_file_len(const char *path) {
	fs::path p(path);
	return fs::file_size(p);
}

void get_master_key(const char *path, unsigned char *master_key) {
    size_t file_len = get_file_len(path);
    check_fatal_err(file_len != MASTER_KEY_LEN,
                    "key file must have exactly 256 bytes.");

    nowide::ifstream in_file(path, std::ios::binary);
    in_file.seekg(0, std::ios::beg);
    in_file.read((char *)master_key, file_len);
    check_fatal_err(!in_file, "cannot read master key from file.");
    in_file.close();
}

bool file_exists(std::string str) {
    fs::path p(str);
    return fs::exists(p);
}

void encrypt(nowide::ifstream &in_file, nowide::ofstream &out_file,
             unsigned char *master_key);
void encrypt_chunk(std::vector<unsigned char> &chunk, size_t chunk_len,
                   nowide::ofstream &out_file,
                   CryptoPP::Threefish1024::Encryption &t3f,
                   CryptoPP::HC256::Encryption &hc256,
                   CryptoPP::HMAC<CryptoPP::SHA3_512> &sha3_hmac);

void decrypt(nowide::ifstream &in_file, nowide::ofstream &out_file,
             unsigned char *master_key, size_t infile_len);
void decrypt_chunk(std::vector<unsigned char> &chunk, size_t chunk_len,
                   nowide::ofstream &out_file,
                   CryptoPP::Threefish1024::Encryption &t3f,
                   CryptoPP::HC256::Encryption &hc256,
                   CryptoPP::HMAC<CryptoPP::SHA3_512> &sha3_hmac);

int main(int argc, char **argv) {
    unsigned char master_key[MASTER_KEY_LEN];

    try {
        nowide::args args(argc, argv);
        if (argc == 3 && strcmp(argv[1], "-mk") == 0) {
            CryptoPP::OS_GenerateRandomBlock(false, master_key, MASTER_KEY_LEN);
            nowide::ofstream out_file(argv[2], std::ios::binary);
            out_file.write((char *)master_key, MASTER_KEY_LEN);
            out_file.close();
            check_fatal_err(!out_file, "cannot write master key to file.");

        } else if (argc == 8 &&
                   (strcmp(argv[1], "-e") == 0 || strcmp(argv[1], "-d") == 0) &&
                   strcmp(argv[2], "-k") == 0 && strcmp(argv[4], "-i") == 0 &&
                   strcmp(argv[6], "-o") == 0) {

            get_master_key(argv[3], master_key);

            if (file_exists(std::string(argv[7]))) {
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

            nowide::ifstream in_file(argv[5], std::ios::binary);
            nowide::ofstream out_file(argv[7], std::ios::binary);

            if (strcmp(argv[1], "-e") == 0) {
                encrypt(in_file, out_file, master_key);
            } else if (strcmp(argv[1], "-d") == 0) {
            	size_t infile_len = get_file_len(argv[5]) - (HEADER_LEN + SALT_LEN + HMAC_HASH_LEN);
                decrypt(in_file, out_file, master_key, infile_len);
            }

            in_file.close();
            out_file.close();
            check_fatal_err(!out_file, "cannot write to file.");

        } else {
            check_fatal_err(true, "unknown options.");
        }

    } catch (CryptoPP::Exception const &ex) {
        nowide::cerr << "CryptoPP::Exception caught: " << ex.what()
                     << std::endl;
        exit(-1);
    } catch (std::exception const &ex) {
        nowide::cerr << "std::exception caught: " << ex.what() << std::endl;
        exit(-2);
    }

    return EXIT_SUCCESS;
}

void encrypt(nowide::ifstream &in_file, nowide::ofstream &out_file,
             unsigned char *master_key) {

    out_file.write((char *)header, HEADER_LEN);
    unsigned char salt[SALT_LEN];
    CryptoPP::OS_GenerateRandomBlock(false, salt, SALT_LEN);
    out_file.write((char *)salt, SALT_LEN);

    unsigned char enc_key[ENC_KEY_LEN];
    check_fatal_err(argon2id_hash_raw(T, M, P, master_key, MASTER_KEY_LEN, salt,
                                      SALT_LEN, enc_key,
                                      ENC_KEY_LEN) != ARGON2_OK,
                    "Argon2 failed.");

    CryptoPP::ConstByteArrayParameter tweak(&enc_key[T3F_KEY_LEN],
                                            T3F_TWEAK_LEN, false);
    CryptoPP::AlgorithmParameters params =
        CryptoPP::MakeParameters(CryptoPP::Name::Tweak(), tweak);
    CryptoPP::Threefish1024::Encryption t3f(enc_key, T3F_KEY_LEN);
    t3f.SetTweak(params);

    CryptoPP::HC256::Encryption hc256;
    hc256.SetKeyWithIV(&enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN], HC256_KEY_LEN,
                       &enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN + HC256_KEY_LEN],
                       HC256_IV_LEN);

    CryptoPP::HMAC<CryptoPP::SHA3_512> sha3_hmac(
        &enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN + HC256_KEY_LEN + HC256_IV_LEN],
        HMAC_KEY_LEN);
    sha3_hmac.Update(header, HEADER_LEN);
    sha3_hmac.Update(salt, SALT_LEN);

    std::vector<unsigned char> chunk(CHUNK_LEN);
    size_t chunk_len = CHUNK_LEN;
    while (1) {
        in_file.read((char *)chunk.data(), CHUNK_LEN);
        if (!in_file) {
            chunk_len = in_file.gcount();
        }
        encrypt_chunk(chunk, chunk_len, out_file, t3f, hc256, sha3_hmac);
        if (!in_file) {
        	break;
        }
    }

    CryptoPP::byte hmac_hash[HMAC_HASH_LEN];
    sha3_hmac.Final(hmac_hash);
    out_file.write((char *)hmac_hash, HMAC_HASH_LEN);
}

void encrypt_chunk(std::vector<unsigned char> &chunk, size_t chunk_len,
                   nowide::ofstream &out_file,
                   CryptoPP::Threefish1024::Encryption &t3f,
                   CryptoPP::HC256::Encryption &hc256,
                   CryptoPP::HMAC<CryptoPP::SHA3_512> &sha3_hmac) {
    unsigned char ctr[T3F_BLOCK_LEN];
    memset(ctr, 0, T3F_BLOCK_LEN);
    unsigned char out[T3F_BLOCK_LEN];

    uint32_t i = 0;
    size_t in_len = chunk_len;
    for (; in_len >= T3F_BLOCK_LEN; ++i, in_len -= T3F_BLOCK_LEN) {
    	hc256.ProcessData(ctr, ctr, T3F_BLOCK_LEN);
        t3f.ProcessBlock(ctr);
        for (uint32_t j = 0; j < T3F_BLOCK_LEN; ++j) {
            out[j] = ctr[j] ^ chunk[i * T3F_BLOCK_LEN + j];
        }
        sha3_hmac.Update(out, T3F_BLOCK_LEN);
        out_file.write((char *)out, T3F_BLOCK_LEN);
    }
    if (in_len > 0) {
    	hc256.ProcessData(ctr, ctr, T3F_BLOCK_LEN);
        t3f.ProcessBlock(ctr);
        for (uint32_t j = 0; j < in_len; ++j) {
            out[j] = ctr[j] ^ chunk[i * T3F_BLOCK_LEN + j];
        }
        sha3_hmac.Update(out, in_len);
        out_file.write((char *)out, in_len);
    }
}

void decrypt(nowide::ifstream &in_file, nowide::ofstream &out_file,
             unsigned char *master_key, size_t infile_len) {

	unsigned char in_header[HEADER_LEN];
	in_file.read((char *)in_header, HEADER_LEN);
    check_fatal_err(!in_file, "cannot read from file.");
    check_fatal_err(memcmp(in_header, header, HEADER_LEN) != 0,
                    "wrong header.");
    unsigned char salt[SALT_LEN];
    in_file.read((char *)salt, SALT_LEN);
    check_fatal_err(!in_file, "cannot read from file.");

    unsigned char enc_key[ENC_KEY_LEN];
    check_fatal_err(argon2id_hash_raw(T, M, P, master_key, MASTER_KEY_LEN, salt,
                                      SALT_LEN, enc_key,
                                      ENC_KEY_LEN) != ARGON2_OK,
                    "Argon2 failed.");

    CryptoPP::ConstByteArrayParameter tweak(&enc_key[T3F_KEY_LEN],
                                            T3F_TWEAK_LEN, false);
    CryptoPP::AlgorithmParameters params =
        CryptoPP::MakeParameters(CryptoPP::Name::Tweak(), tweak);
    CryptoPP::Threefish1024::Encryption t3f(enc_key, T3F_KEY_LEN);
    t3f.SetTweak(params);

    CryptoPP::HC256::Encryption hc256;
    hc256.SetKeyWithIV(&enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN], HC256_KEY_LEN,
                       &enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN + HC256_KEY_LEN],
                       HC256_IV_LEN);

    CryptoPP::HMAC<CryptoPP::SHA3_512> sha3_hmac(
        &enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN + HC256_KEY_LEN + HC256_IV_LEN],
        HMAC_KEY_LEN);
    sha3_hmac.Update(header, HEADER_LEN);
    sha3_hmac.Update(salt, SALT_LEN);

    std::vector<unsigned char> chunk(CHUNK_LEN);
    size_t chunk_len = CHUNK_LEN;
    size_t num_read = infile_len / CHUNK_LEN + (infile_len % CHUNK_LEN != 0);
    for (size_t i = 0; i < num_read; ++i) {
        if (i == num_read - 1) {
            chunk_len = infile_len - i * CHUNK_LEN;
        }
        in_file.read((char *)chunk.data(), chunk_len);
        check_fatal_err(!in_file, "cannot read from file.");
        decrypt_chunk(chunk, chunk_len, out_file, t3f, hc256, sha3_hmac);
    }

    CryptoPP::byte hmac_hash[HMAC_HASH_LEN];
    sha3_hmac.Final(hmac_hash);
    in_file.read((char *)chunk.data(), HMAC_HASH_LEN);
    check_fatal_err(!in_file, "cannot read from file.");
    check_fatal_err(memcmp(hmac_hash, chunk.data(), HMAC_HASH_LEN) != 0,
                    "wrong Skein MAC.");
}

void decrypt_chunk(std::vector<unsigned char> &chunk, size_t chunk_len,
                   nowide::ofstream &out_file,
                   CryptoPP::Threefish1024::Encryption &t3f,
                   CryptoPP::HC256::Encryption &hc256,
                   CryptoPP::HMAC<CryptoPP::SHA3_512> &sha3_hmac) {

	unsigned char ctr[T3F_BLOCK_LEN];
    memset(ctr, 0, T3F_BLOCK_LEN);
    unsigned char out[T3F_BLOCK_LEN];

    uint32_t i = 0;
    size_t in_len = chunk_len;
    for (; in_len >= T3F_BLOCK_LEN; ++i, in_len -= T3F_BLOCK_LEN) {
    	hc256.ProcessData(ctr, ctr, T3F_BLOCK_LEN);
        t3f.ProcessBlock(ctr);
        for (uint32_t j = 0; j < T3F_BLOCK_LEN; ++j) {
            out[j] = ctr[j] ^ chunk[i * T3F_BLOCK_LEN + j];
        }
        
        out_file.write((char *)out, T3F_BLOCK_LEN);
    }
    if (in_len > 0) {
    	hc256.ProcessData(ctr, ctr, T3F_BLOCK_LEN);
        t3f.ProcessBlock(ctr);
        for (uint32_t j = 0; j < in_len; ++j) {
            out[j] = ctr[j] ^ chunk[i * T3F_BLOCK_LEN + j];
        }
        out_file.write((char *)out, in_len);
    }
    sha3_hmac.Update(chunk.data(), chunk_len);
}