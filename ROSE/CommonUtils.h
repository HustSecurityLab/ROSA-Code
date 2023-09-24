#ifndef COMMON_H
#define COMMON_H

#include <iostream>
#include <string>
#include <grpc/grpc.h>
#include <grpcpp/create_channel.h>
#define WRITE_BUFFER_SIZE (10*1024*1024)

enum OP
{
    op_del = 0,
    op_add = 1,
    op_srh = 2
};

int PRF_F(unsigned char *out, const unsigned char *key, const std::string &keyword, const std::string &id, OP op);

int Hash_H(unsigned char *out, int out_len, const unsigned char *in1, const unsigned char *R);

int Hash_G(unsigned char *out, const unsigned char *data, const unsigned char *R);

int print_hex(unsigned char *data, int len);

int Xor(int _bytes, const unsigned char *in1, const unsigned char *in2, unsigned char *out);

void save_string(FILE*f_out, const std::string & str);

std::string load_string(FILE *f_in);

grpc::ChannelArguments get_channel_args();

#endif
