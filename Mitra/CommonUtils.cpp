#include "CommonUtils.h"
#include <string>
#include <cstring>
#include <cstdlib>
#include <iostream>

extern "C"
{
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
}

static char *buf= nullptr;

void print_hex(const void *data, int len)
{
    unsigned char *p = (unsigned char *) data;
    for (int i = 0; i < len; i++)
    {
        printf("%02X ", p[i]);
    }
    printf("\n");
}

void print_hash(const std::string &data)
{
    unsigned char buf[64];

    SHA256((const unsigned char *) data.c_str(), data.length(), buf);

    print_hex(buf, 32);
}

void save_string(FILE *f_out, const std::string &str)
{
    size_t size = str.size();

    fwrite(&size, sizeof(size), 1, f_out);
    fwrite(str.c_str(), sizeof(char), size, f_out);
}

void load_string(std::string &str, FILE *f_in)
{
    if (buf == nullptr)
        buf = (char *) calloc(1024 * 1024 * 10, sizeof(char));

    size_t size;

    fread(&size, sizeof(size), 1, f_in);
    fread(buf, sizeof(char), size, f_in);
    str.assign(buf, size);
}

grpc::ChannelArguments get_channel_args()
{
    grpc::ChannelArguments args;
    args.SetInt(GRPC_ARG_HTTP2_WRITE_BUFFER_SIZE, WRITE_BUFFER_SIZE);
    args.SetInt(GRPC_ARG_HTTP2_STREAM_LOOKAHEAD_BYTES, 1024*1024);
    args.SetInt(GRPC_ARG_HTTP2_MAX_FRAME_SIZE, 64*1024);
    args.SetInt(GRPC_ARG_HTTP2_MAX_PING_STRIKES, 0);
    args.SetInt(GRPC_ARG_HTTP2_MAX_PINGS_WITHOUT_DATA, 0);
    args.SetInt(GRPC_ARG_KEEPALIVE_TIMEOUT_MS, 80000);
    args.SetInt(GRPC_ARG_KEEPALIVE_TIME_MS, 15000);
    return args;
}