#include <cstring>
#include <filesystem>
#include <string>

#include <cryptopp/hrtimer.h>
#include <cryptopp/kalyna.h>
#include <cryptopp/misc.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/sha3.h>
#include <cryptopp/threefish.h>

#include "argon2/argon2.h"
#include "nowide/args.hpp"
#include "nowide/fstream.hpp"
#include "nowide/iostream.hpp"

namespace fs = std::filesystem;

const unsigned int T3F_TWEAK_LEN = 16;
const unsigned int T3F_KEY_LEN = 128;
const unsigned int T3F_BLOCK_LEN = 128;
const unsigned int T3F_CTR_IV_LEN = 128;
const unsigned int NUM_BLOCKS = 2048;
const unsigned int CHUNK_LEN = NUM_BLOCKS * T3F_BLOCK_LEN;

const unsigned int SALT_LEN = 32;
const unsigned int HEADER_LEN = 6;
const unsigned int MASTER_KEY_LEN = 256;

const unsigned int KL_KEY_LEN = 64;
const unsigned int KL_CTR_IV_LEN = 64;

const unsigned int HMAC_KEY_LEN = 64;
const unsigned int HMAC_HASH_LEN = 64;
const unsigned int ENC_KEY_LEN = T3F_KEY_LEN + T3F_TWEAK_LEN + T3F_CTR_IV_LEN +
                                 KL_KEY_LEN + KL_CTR_IV_LEN + HMAC_KEY_LEN;

const unsigned char header[HEADER_LEN] = {'t', '3', 'f', 'c', '0', '1'};

const uint32_t T = 10;
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

void get_master_key(const char *path, CryptoPP::SecByteBlock &master_key) {
    size_t file_len = get_file_len(path);
    check_fatal_err(file_len != MASTER_KEY_LEN,
                    "key file must have exactly 256 bytes.");
    nowide::ifstream in_file(path, std::ios::binary);
    in_file.read((char *)master_key.data(), file_len);
    check_fatal_err(!in_file || in_file.gcount() != MASTER_KEY_LEN,
                    "cannot read master key from file.");
    in_file.close();
}

bool file_exists(std::string str) {
    fs::path p(str);
    return fs::exists(p);
}

void encrypt(nowide::ifstream &in_file, nowide::ofstream &out_file,
             CryptoPP::SecByteBlock &master_key);
void decrypt(size_t file_len, nowide::ifstream &in_file,
             nowide::ofstream &out_file, CryptoPP::SecByteBlock &master_key);

int main(int argc, char **argv) {

    CryptoPP::SecByteBlock master_key(MASTER_KEY_LEN);
    try {
        nowide::args args(argc, argv);
        if (argc == 3 && strcmp(argv[1], "-mk") == 0) {
            CryptoPP::OS_GenerateRandomBlock(false, master_key, MASTER_KEY_LEN);
            nowide::ofstream out_file(argv[2], std::ios::binary);
            out_file.write((char *)master_key.data(), MASTER_KEY_LEN);
            out_file.close();
            check_fatal_err(!out_file, "cannot write master key to file.");

        } else if (argc == 8 &&
                   (strcmp(argv[1], "-e") == 0 || strcmp(argv[1], "-d") == 0) &&
                   strcmp(argv[2], "-k") == 0 && strcmp(argv[4], "-i") == 0 &&
                   strcmp(argv[6], "-o") == 0) {

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

            get_master_key(argv[3], master_key);
            nowide::ifstream in_file(argv[5], std::ios::binary);
            nowide::ofstream out_file(argv[7], std::ios::binary);

            if (strcmp(argv[1], "-e") == 0) {
                encrypt(in_file, out_file, master_key);
            } else if (strcmp(argv[1], "-d") == 0) {
                size_t file_len = get_file_len(argv[5]);
                decrypt(file_len, in_file, out_file, master_key);
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
             CryptoPP::SecByteBlock &master_key) {

    out_file.write((char *)header, HEADER_LEN);
    unsigned char salt[SALT_LEN];
    CryptoPP::OS_GenerateRandomBlock(false, salt, SALT_LEN);
    out_file.write((char *)salt, SALT_LEN);

    CryptoPP::SecByteBlock enc_key(ENC_KEY_LEN);

    CryptoPP::Timer timer;
    timer.StartTimer();

    check_fatal_err(argon2id_hash_raw(T, M, P, master_key.data(),
                                      MASTER_KEY_LEN, salt, SALT_LEN, enc_key.data(),
                                      ENC_KEY_LEN) != ARGON2_OK,
                    "Argon2 failed.");

    double argon2 = timer.ElapsedTimeAsDouble();
    nowide::cout << "argon2  " << argon2 << std::endl;

    CryptoPP::ConstByteArrayParameter tweak(&enc_key[T3F_KEY_LEN],
                                            T3F_TWEAK_LEN, false);
    CryptoPP::AlgorithmParameters t3f_params =
        CryptoPP::MakeParameters(CryptoPP::Name::Tweak(), tweak);
    CryptoPP::Threefish1024::Encryption t3f(enc_key, T3F_KEY_LEN);
    t3f.SetTweak(t3f_params);
    CryptoPP::CTR_Mode_ExternalCipher::Encryption t3f_ctr(
        t3f, &enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN]);

    CryptoPP::CTR_Mode<CryptoPP::Kalyna512>::Encryption kalyna(
        &enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN + T3F_CTR_IV_LEN], KL_KEY_LEN,
        &enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN + T3F_CTR_IV_LEN + KL_KEY_LEN]);

    CryptoPP::HMAC<CryptoPP::SHA3_512> sha3_hmac(
        &enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN + T3F_CTR_IV_LEN + KL_KEY_LEN +
                 KL_CTR_IV_LEN],
        HMAC_KEY_LEN);
    sha3_hmac.Update(header, HEADER_LEN);
    sha3_hmac.Update(salt, SALT_LEN);

    CryptoPP::SecByteBlock chunk(CHUNK_LEN);
    size_t chunk_len = CHUNK_LEN;
    while (in_file) {
        in_file.read((char *)chunk.data(), CHUNK_LEN);
        chunk_len = in_file.gcount();
        if (chunk_len == 0) {
            break;
        }
        t3f_ctr.ProcessData(chunk.data(), chunk.data(), chunk_len);
        kalyna.ProcessData(chunk.data(), chunk.data(), chunk_len);
        sha3_hmac.Update(chunk.data(), chunk_len);
        out_file.write((char *)chunk.data(), chunk_len);
    }

    CryptoPP::byte hmac_hash[HMAC_HASH_LEN];
    sha3_hmac.Final(hmac_hash);
    out_file.write((char *)hmac_hash, HMAC_HASH_LEN);

    double encrypt = timer.ElapsedTimeAsDouble();
    nowide::cout << "encrypt " << encrypt - argon2 << std::endl;
}

void decrypt(size_t file_len, nowide::ifstream &in_file,
             nowide::ofstream &out_file, CryptoPP::SecByteBlock &master_key) {

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

    CryptoPP::Timer timer;
    timer.StartTimer();

    CryptoPP::SecByteBlock enc_key(ENC_KEY_LEN);
    check_fatal_err(argon2id_hash_raw(T, M, P, master_key.data(),
                                      MASTER_KEY_LEN, salt, SALT_LEN,
                                      enc_key.data(), ENC_KEY_LEN) != ARGON2_OK,
                    "Argon2 failed.");

    double argon2 = timer.ElapsedTimeAsDouble();
    nowide::cout << "argon2  " << argon2 << std::endl;

    CryptoPP::ConstByteArrayParameter tweak(&enc_key[T3F_KEY_LEN],
                                            T3F_TWEAK_LEN, false);
    CryptoPP::AlgorithmParameters t3f_params =
        CryptoPP::MakeParameters(CryptoPP::Name::Tweak(), tweak);
    CryptoPP::Threefish1024::Encryption t3f(enc_key, T3F_KEY_LEN);
    t3f.SetTweak(t3f_params);
    CryptoPP::CTR_Mode_ExternalCipher::Encryption t3f_ctr(
        t3f, &enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN]);

    CryptoPP::CTR_Mode<CryptoPP::Kalyna512>::Encryption kalyna(
        &enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN + T3F_CTR_IV_LEN], KL_KEY_LEN,
        &enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN + T3F_CTR_IV_LEN + KL_KEY_LEN]);

    CryptoPP::HMAC<CryptoPP::SHA3_512> sha3_hmac(
        &enc_key[T3F_KEY_LEN + T3F_TWEAK_LEN + T3F_CTR_IV_LEN + KL_KEY_LEN +
                 KL_CTR_IV_LEN],
        HMAC_KEY_LEN);
    sha3_hmac.Update(in_header, HEADER_LEN);
    sha3_hmac.Update(salt, SALT_LEN);

    CryptoPP::SecByteBlock chunk(CHUNK_LEN);
    CryptoPP::SecByteBlock read_hash(HMAC_HASH_LEN);
    size_t chunk_len = CHUNK_LEN;
    size_t plaintext_len = file_len - (HEADER_LEN + SALT_LEN + HMAC_HASH_LEN);
    size_t num_read =
        plaintext_len / CHUNK_LEN + (plaintext_len % CHUNK_LEN != 0);
    for (size_t i = 0; i < num_read; ++i) {
        if (i == num_read - 1) {
            chunk_len = plaintext_len - i * CHUNK_LEN;
        }
        in_file.read((char *)chunk.data(), chunk_len);
        check_fatal_err(in_file.gcount() % chunk_len != 0, "cannot read file.");
        sha3_hmac.Update(chunk.data(), chunk_len);
        kalyna.ProcessData(chunk.data(), chunk.data(), chunk_len);
        t3f_ctr.ProcessData(chunk.data(), chunk.data(), chunk_len);
        out_file.write((char *)chunk.data(), chunk_len);
    }

    in_file.read((char *)chunk.data(), HMAC_HASH_LEN);
    CryptoPP::byte hmac_hash[HMAC_HASH_LEN];
    sha3_hmac.Final(hmac_hash);
    check_fatal_err(
        CryptoPP::VerifyBufsEqual(hmac_hash, chunk, HMAC_HASH_LEN) != true,
        "wrong HMAC.");

    double decrypt = timer.ElapsedTimeAsDouble();
    nowide::cout << "decrypt " << decrypt - argon2 << std::endl;
}