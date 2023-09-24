#include "vORAMBucket.h"
#include <string>
#include <iostream>
extern "C"
{
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
}

using namespace std;

Bucket::Bucket() : nodesize(0), keylen(0), lenlen(0), idlen(0), remaining(0), data_(NULL)
{
}

Bucket::Bucket(const Bucket &_b) : nodesize(_b.nodesize), keylen(_b.keylen), lenlen(_b.lenlen), idlen(_b.idlen), remaining(_b.remaining)
{
    if (_b.data_ == NULL)
        this->data_ = NULL;
    else
    {
        this->data_ = (unsigned char *)calloc(nodesize, sizeof(unsigned char));
        memcpy(this->data_, _b.data_, nodesize);
    }
}

Bucket::Bucket(int nodesize, int keylen, int lenlen, int idlen)
{
    this->data_ = NULL;
    this->nodesize = nodesize;
    this->keylen = keylen;
    this->lenlen = lenlen;
    this->idlen = idlen;
    this->remaining = nodesize - 2 * keylen;

    this->data_ = (unsigned char *)calloc(nodesize, sizeof(unsigned char));
}

Bucket::Bucket(Bucket &&_b) noexcept
{
    this->nodesize = _b.nodesize;
    this->keylen = _b.keylen;
    this->lenlen = _b.lenlen;
    this->idlen = _b.idlen;
    this->remaining = _b.remaining;
    this->data_ = _b.data_;

    _b.data_ = NULL;
}

Bucket::~Bucket()
{
    if(this->data_)
        free(this->data_);
    this->data_ = NULL;
}

Bucket &Bucket::operator=(const Bucket &_b)
{
    if (this == &_b)
        return *this;

    this->data_ = NULL;
    this->nodesize = _b.nodesize;
    this->keylen = _b.keylen;
    this->lenlen = _b.lenlen;
    this->idlen = _b.idlen;
    this->remaining = _b.remaining;

    this->data_ = (unsigned char *)calloc(nodesize, sizeof(unsigned char));

    memcpy(this->data_, _b.data_, nodesize);

    return *this;
}

Bucket &Bucket::operator=(Bucket &&_b) noexcept
{
    if (this == &_b)
        return *this;

    this->nodesize = _b.nodesize;
    this->keylen = _b.keylen;
    this->lenlen = _b.lenlen;
    this->idlen = _b.idlen;
    this->remaining = _b.remaining;
    this->data_ = _b.data_;

    _b.data_ = NULL;
    return *this;
}

unsigned char *Bucket::key1()
{
    if (this->data_)
        return this->data_;
    else
        return NULL;
}

unsigned char *Bucket::key2()
{
    if (this->data_)
        return this->data_ + keylen;
    else
        return NULL;
}

unsigned char *Bucket::id(int blob_no)
{
    int p_data = keylen * 2;
    int cur_blob = 0;
    int len;

    while (p_data < nodesize)
    {
        // If this is the first empty blob
        if (*(data_ + p_data) == 0)
            return NULL;

        if (cur_blob == blob_no)
            return data_ + p_data;

        p_data += idlen;
        len = 0;
        for (int i = 0; i < lenlen; i++)
        {
            len += (int(*(data_ + p_data + i))) << ((lenlen - 1 - i) * 8);
        }
        p_data += len + lenlen;
        cur_blob += 1;
    }
    return NULL;
}
int Bucket::len(int blob_no)
{
    unsigned char *data_p_ = this->id(blob_no);
    if (!data_p_)
        return 0;
    int len = 0;
    for (int i = 0; i < lenlen; i++)
        len += (int(*(data_p_ + idlen + i))) << ((lenlen - 1 - i) * 8);
    return len;
}

unsigned char *Bucket::blob(int blob_no)
{
    unsigned char *data_p_ = this->id(blob_no);
    if (!data_p_)
        return NULL;
    return data_p_ + lenlen + idlen;
}

int Bucket::append_blob(unsigned char *id, unsigned char *data, int len)
{
    unsigned char *empty_id;
    int write_len;
    int tmp_len;

    if (idlen + lenlen >= remaining)
        return 0;

    empty_id = first_empty_id();
    memcpy(empty_id, id, idlen);

    if ((remaining - idlen - lenlen) >= len)
        write_len = len;
    else
        write_len = remaining - idlen - lenlen;

    tmp_len = write_len;
    for (int i = 0; i < lenlen; i++)
    {
        *(empty_id + idlen + lenlen - 1 - i) = ((unsigned char)(tmp_len & 255));
        tmp_len = tmp_len >> 8;
    }

    memcpy(empty_id + idlen + lenlen, data, write_len);
    remaining -= idlen + lenlen + write_len;

    return write_len;
}

int Bucket::len(unsigned char *id)
{
    int p_data = keylen * 2;
    int len = 0;

    while (p_data < nodesize)
    {
        if (*(data_ + p_data) == 0)
            return 0;

        len = 0;
        for (int i = 0; i < lenlen; i++)
            len += (int(*(data_ + idlen + p_data + i))) << ((lenlen - 1 - i) * 8);

        if (memcmp(id, data_ + p_data, idlen) == 0)
            return len;
        p_data += idlen + lenlen + len;
    }
    return 0;
}

unsigned char *Bucket::blob(unsigned char *id)
{
    int p_data = keylen * 2;
    int len;

    while (p_data < nodesize)
    {
        if (*(data_ + p_data) == 0)
            return NULL;
        if (memcmp(id, data_ + p_data, idlen) == 0)
            return data_ + p_data + idlen + lenlen;

        p_data += idlen;
        len = 0;
        for (int i = 0; i < lenlen; i++)
            len += (int(*(data_ + p_data + i))) << ((lenlen - 1 - i) * 8);
        p_data += lenlen + len;
    }
    return NULL;
}

unsigned char *Bucket::first_empty_id()
{
    int p_data = keylen * 2;
    int len;

    while (p_data < nodesize)
    {
        if (*(data_ + p_data) == 0)
            return data_ + p_data;

        p_data += idlen;
        len = 0;
        for (int i = 0; i < lenlen; i++)
            len += (int(*(data_ + p_data + i))) << ((lenlen - 1 - i) * 8);

        p_data += len + lenlen;
    }
    return NULL;
}

void Bucket::Setup(int nodesize, int keylen, int lenlen, int idlen)
{
    if (data_)
        free(data_);
    this->nodesize = nodesize;
    this->keylen = keylen;
    this->lenlen = lenlen;
    this->idlen = idlen;
    this->remaining = nodesize - keylen * 2;
    data_ = (unsigned char *)calloc(nodesize, sizeof(char));
}

void Bucket::to_encrypted_string(string &out, const unsigned char *key, int keylen)
{
    unsigned char buf1[5120], buf2[5120];
    unsigned char IV[16];
    EVP_CIPHER_CTX *ctx;
    int len, len_out, len_out2;
    //string verify = "1234567890abcdef";

    if ((!data_) || (sizeof(int) * 5 + nodesize > 5000))
    {
        out = "";
        return;
    }

    memset(buf2, 0, 5120);
    memset(buf1, 0, 5120);

    RAND_bytes(IV, 16);
    memcpy(buf2, IV, 16);
    memcpy(buf1, this, 5 * sizeof(int));
    memcpy(buf1 + 5 * sizeof(int), data_, nodesize);
    //memcpy(buf1 + 5*sizeof(int) + nodesize, verify.c_str(), 16);

    //len = 5 * sizeof(int) + nodesize + 16;
    len = 5* sizeof(int) + nodesize;

    ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, IV);

    EVP_EncryptUpdate(ctx, buf2 + 16, &len_out, buf1, len);
    EVP_EncryptFinal_ex(ctx, buf2 + 16 + len_out, &len_out2);

    out.assign((const char *)buf2, 16 + len_out + len_out2);
    EVP_CIPHER_CTX_free(ctx);
}

void Bucket::from_encrypted_string(const std::string &in, const unsigned char *key, int keylen)
{
    unsigned char buf1[5120];
    unsigned char IV[16];
    EVP_CIPHER_CTX *ctx;
    int len_out, len_out2;
    //string verify = "1234567890abcdef";

    memset(buf1, 0, 5120);
    memcpy(IV, in.c_str(), 16);

    ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, IV);

    EVP_DecryptUpdate(ctx, buf1, &len_out, (const unsigned char *)in.c_str() + 16, in.length() - 16);    
    EVP_DecryptFinal_ex(ctx, buf1+len_out,&len_out2);
    
    EVP_CIPHER_CTX_free(ctx);

    memcpy(this, buf1, 5 * sizeof(int));
    if(!data_)
        data_ = (unsigned char *)calloc(this->nodesize, sizeof(char));
    memcpy(data_, buf1 + 5 * sizeof(int), nodesize);
    /*if(memcmp(buf1 + 5*sizeof(int) + nodesize, verify.c_str(), 16) != 0)
        cout << "vORAM bucket decrypt failed!" << endl;*/
}