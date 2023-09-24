#include <cstring>
#include "CommonUtils.h"

#include <string>

extern "C"
{
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
};

void encrypt_id(unsigned char *buf_out, const std::string &ind, const unsigned char *key)
{
    unsigned char IV[16], buf[128], plain[32];
    EVP_CIPHER_CTX *ctx;
    int len_out, len_out1;

    memset(plain, 0, 32);
    memset(buf, 0, 128);

    ctx = EVP_CIPHER_CTX_new();

    RAND_bytes(IV, 16);
    memcpy(buf, IV, 16);

    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), nullptr, key, IV);

    memcpy(plain, ind.c_str(), ind.size() > 12 ? 12 : ind.size());
    plain[12] = 'c';
    plain[13] = '#';
    plain[14] = '*';
    plain[15] = '$';

    EVP_EncryptUpdate(ctx, buf + 16, &len_out, plain, 16);
    EVP_EncryptFinal_ex(ctx, buf + 16 + len_out, &len_out1);

    memcpy(buf_out, buf, 32);
    EVP_CIPHER_CTX_free(ctx);
}

bool decrypt_id(std::string &ind_out, const unsigned char *cip, const unsigned char *key)
{
    unsigned char IV[16], plain[64];
    EVP_CIPHER_CTX *ctx;
    int len_out, len_out1;

    memset(plain, 0, 32);

    ctx = EVP_CIPHER_CTX_new();
    memcpy(IV, cip, 16);
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), nullptr, key, IV);

    EVP_DecryptUpdate(ctx, plain, &len_out, cip + 16, 16);
    EVP_DecryptFinal_ex(ctx, plain + len_out, &len_out1);

    EVP_CIPHER_CTX_free(ctx);

    if (!((plain[12] == 'c') && (plain[13] == '#') && (plain[14] == '*') && (plain[15] == '$')))
        return false;

    plain[12] = 0;

    ind_out = (char *) plain;

    return true;
}

void aes_cbc_prf(unsigned char *out, const unsigned char *key, const unsigned char *data)
{
    unsigned char IV[16], buf[64];
    EVP_CIPHER_CTX *ctx;
    int len_out;

    memset(IV, 0x1f, 16);

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), nullptr, key, IV);
    EVP_EncryptUpdate(ctx, buf, &len_out, data, 16);
    EVP_EncryptFinal_ex(ctx, buf + 16, &len_out);
    EVP_CIPHER_CTX_free(ctx);

    memcpy(out, buf, 16);
}

grpc::ChannelArguments get_channel_args()
{
    grpc::ChannelArguments args;
    args.SetInt(GRPC_ARG_HTTP2_WRITE_BUFFER_SIZE, WRITE_BUFER_SIZE);
    args.SetInt(GRPC_ARG_HTTP2_STREAM_LOOKAHEAD_BYTES, 1024*1024);
    args.SetInt(GRPC_ARG_HTTP2_MAX_FRAME_SIZE, 64*1024);
    args.SetInt(GRPC_ARG_HTTP2_MAX_PING_STRIKES, 0);
    args.SetInt(GRPC_ARG_HTTP2_MAX_PINGS_WITHOUT_DATA, 0);
    args.SetInt(GRPC_ARG_KEEPALIVE_TIMEOUT_MS, 80000);
    args.SetInt(GRPC_ARG_KEEPALIVE_TIME_MS, 15000);
    return args;
}

void print_hex(const unsigned char *data, int len)
{
    for (int i = 0; i < len; i++)
    {
        printf("%02X ", data[i]);
    }
    printf("\n");
}

void print_hash(const std::string &data)
{
    unsigned char buf[64];

    SHA256((const unsigned char *) data.c_str(), data.length(), buf);

    print_hex(buf, 32);
}