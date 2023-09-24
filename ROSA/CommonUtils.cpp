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

int aes_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *key, unsigned char *iv,
                unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len = 0;

    int ciphertext_len;

    /* Create and initialise the context */
    ctx = EVP_CIPHER_CTX_new();

    /* Initialise the encryption operation. */
    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);

    /* Encrypt the message */
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;

    /* Finalise the encryption */
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int aes_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *key, unsigned char *iv,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len = 0;

    int plaintext_len;

    /* Create and initialise the context */
    ctx = EVP_CIPHER_CTX_new();

    /* Initialise the decryption operation. */
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv);

    /* decrypt the message */
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;

    /* Finalise the encryption */
    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

void sha3_digest(const unsigned char *plaintext, int plaintext_len,
                 unsigned char *digest)
{
    unsigned int length;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha3_256(), nullptr);
    EVP_DigestUpdate(ctx, plaintext, plaintext_len);
    EVP_DigestFinal_ex(ctx, digest, &length);
    EVP_MD_CTX_destroy(ctx);
}

unsigned int hmac_digest(unsigned char *digest, const unsigned char *plaintext,
                         int plaintext_len, const unsigned char *key, int key_len)
{
    HMAC_CTX *ctx;

    unsigned int len;

    if (!HMAC(EVP_sha256(), key, key_len, plaintext,
              plaintext_len, digest, &len))
        len = -1;

    return len;
}

unsigned int key_derivation(unsigned char *plaintext, int plaintext_len,
                            unsigned char *key, int key_len,
                            unsigned char *digest)
{
    HMAC_CTX *ctx;

    unsigned int len;
    unsigned char buf[32];

    if (!HMAC(EVP_sha3_256(), key, key_len, plaintext, plaintext_len,
              buf, &len))
    {
        memset(buf, 0, 16);
        len = -1;
    }

    memcpy(digest, buf, 16);

    return len;
}

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

    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, IV);

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
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, IV);

    EVP_DecryptUpdate(ctx, plain, &len_out, cip + 16, 16);
    EVP_DecryptFinal_ex(ctx, plain + len_out, &len_out1);

    EVP_CIPHER_CTX_free(ctx);

    if (!((plain[12] == 'c') && (plain[13] == '#') && (plain[14] == '*') && (plain[15] == '$')))
        return false;

    plain[12] = 0;

    ind_out = (char *) plain;

    return true;
}

int PRF_F(unsigned char *out, const unsigned char *key, const std::string &keyword, int cnt)
{
    unsigned int out_len;
    std::string tmp;
    unsigned int len = 0;

    tmp.reserve(keyword.length() + 20);

    tmp = keyword + "@" + std::to_string(cnt);
    if (!HMAC(EVP_sha256(), key, 16,(const unsigned char*) tmp.c_str(),
              tmp.length(), out, &len))
        len = -1;

    return len;
}

grpc::ChannelArguments get_channel_args(int arg)
{
    grpc::ChannelArguments args;
    args.SetInt(GRPC_ARG_HTTP2_WRITE_BUFFER_SIZE, WRITE_BUFER_SIZE);
    args.SetInt(GRPC_ARG_HTTP2_STREAM_LOOKAHEAD_BYTES, 1024*1024);
    args.SetInt(GRPC_ARG_HTTP2_MAX_FRAME_SIZE, 64*1024);
    args.SetInt(GRPC_ARG_HTTP2_MAX_PING_STRIKES, 0);
    args.SetInt(GRPC_ARG_HTTP2_MAX_PINGS_WITHOUT_DATA, 0);
    args.SetInt(GRPC_ARG_KEEPALIVE_TIMEOUT_MS, 80000);
    args.SetInt(GRPC_ARG_KEEPALIVE_TIME_MS, 15000 + arg);
    return args;
}