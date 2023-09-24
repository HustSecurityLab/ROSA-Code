#ifndef COMMONUTILS_H
#define COMMONUTILS_H

#include <string>
#include <grpc/grpc.h>
#include <grpcpp/create_channel.h>
extern "C"
{
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
};

//41000 10^-5
#define GGM_SIZE 982469
#define OMAP_CAP 1200000
#define AES_BLOCK_SIZE 16
#define DIGEST_SIZE 32
//#define GGM_SIZE 191701
#define WRITE_BUFER_SIZE (10*1024*1024)

enum RosaOp
{
    RosaAdd,
    RosaDel
};

void print_hex(const void *data, int len);

void print_hash(const std::string &data);

void save_string(FILE*f_out, const std::string & str);
void load_string(std::string &str, FILE *f_in);

void sha3_digest(const unsigned char *plaintext, int plaintext_len,
                   unsigned char *digest);

unsigned int hmac_digest(unsigned char *digest, const unsigned char *plaintext, int plaintext_len,
                         const unsigned char *key, int key_len);

unsigned int key_derivation(unsigned char *plaintext, int plaintext_len,
                            unsigned char *key, int key_len,
                            unsigned char *digest);

void encrypt_id(unsigned char *buf_out, const std::string &ind, const unsigned char *key);

bool decrypt_id(std::string &ind_out, const unsigned char* cip, const unsigned char *key);

int PRF_F(unsigned char *out, const unsigned char *key, const std::string &keyword, int cnt);

grpc::ChannelArguments get_channel_args(int arg=0);

#endif