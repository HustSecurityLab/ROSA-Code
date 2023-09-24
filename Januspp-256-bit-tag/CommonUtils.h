#ifndef JANUSPP256_COMMONUTILS_H
#define JANUSPP256_COMMONUTILS_H

#include <string>
#include "pun_encryption.h"
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

enum OP
{
    op_add,
    op_del
};

#define MAX_DELETESUPPORT (2000)
#define WRITE_BUFER_SIZE (10*1024*1024)

void encrypt_id(unsigned char *buf_out, const std::string &ind, const unsigned char *key);

bool decrypt_id(std::string &ind_out, const unsigned char* cip, const unsigned char *key);

void aes_cbc_prf(unsigned char *out, const unsigned char *key, const unsigned char *data);

grpc::ChannelArguments get_channel_args();

void print_hex(const unsigned char *data, int len);

void print_hash(const std::string &data);

#endif
