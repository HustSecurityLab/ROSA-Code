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


#define WRITE_BUFFER_SIZE (10*1024*1024)

enum OP
{
    op_add,
    op_del
};

void print_hex(const void *data, int len);

void print_hash(const std::string &data);

void save_string(FILE*f_out, const std::string & str);
void load_string(std::string &str, FILE *f_in);

grpc::ChannelArguments get_channel_args();

#endif