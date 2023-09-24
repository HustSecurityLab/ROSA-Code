#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <string>
#include <iostream>

extern "C"
{
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
}
#include "DianaClient.h"

using std::cout;
using std::endl;
using std::map;
using std::string;

int DianaClient::Setup()
{
    RAND_bytes(key_master, 16);
    keywords_conuter.clear();

    return 1;
}

int DianaClient::update(std::array<unsigned char, 32> &label, const std::string &keyword)
{
    unsigned char Tw[16], buf_[32], *kw, output[64];
    unsigned int counter;
    ConstrainedPRF c_prf;

    kw = buf_;
    PRF_F_sha256(keyword.c_str(), keyword.size(), buf_);

    if (keywords_conuter.find(keyword) == keywords_conuter.end())
        counter = 0;
    else
        counter = keywords_conuter[keyword] + 1;

    c_prf.Eval(kw, counter, Tw);
    keywords_conuter[keyword] = counter;
    memcpy(buf_, Tw, 16);
    SHA256(buf_, 32, label.data());

    return 1;
}

int DianaClient::trapdoor(const std::string &keyword, ConstrainedKey &trpdr_key, unsigned char *kw1_out)
{
    unsigned char buf_[32];
    int counter;
    ConstrainedPRF c_prf;

    if (keywords_conuter.find(keyword) == keywords_conuter.end())
    {
        trpdr_key.current_permitted = 0;
        memset(kw1_out, 0, 16);
        return 0;
    }

    PRF_F_sha256(keyword.c_str(), keyword.size(), buf_);

    counter = keywords_conuter[keyword];
    c_prf.Constrain(buf_, counter, trpdr_key);

    memcpy(kw1_out, buf_ + 16, 16);

    return 1;
}

void DianaClient::dump_data(FILE *f_out)
{
    unsigned long len_counter = this->keywords_conuter.size();
    unsigned long len_str;
    unsigned int count;

    fwrite(this->key_master, sizeof(char), 16, f_out);

    fwrite(&len_counter, sizeof(char), sizeof(len_counter), f_out);

    for (auto &itr : this->keywords_conuter)
    {
        len_str = itr.first.size();
        count = itr.second;

        fwrite(&len_str, sizeof(char), sizeof(len_str), f_out);
        fwrite(itr.first.c_str(), sizeof(char), len_str, f_out);
        fwrite(&count, sizeof(char), sizeof(count), f_out);
    }
}

void DianaClient::load_data(FILE *f_in)
{
    unsigned long len_counter, len_str;
    unsigned int count;
    char buf1[500];

    this->keywords_conuter.clear();

    fread(this->key_master, sizeof(char), 16, f_in);

    fread(&len_counter, sizeof(char), sizeof(len_counter), f_in);

    for (unsigned long i = 0; i < len_counter; i++)
    {
        string keyword;

        fread(&len_str, sizeof(char), sizeof(len_str), f_in);
        fread(buf1, sizeof(char), len_str, f_in);
        fread(&count, sizeof(char), sizeof(count), f_in);

        buf1[len_str] = 0;
        keyword = buf1;
        this->keywords_conuter[keyword] = count;
    }
}

void DianaClient::PRF_F_sha256(const char *keyword, unsigned int len, unsigned char *out)
{
    unsigned int out_len;

    HMAC(EVP_sha256(), this->key_master, 16, (const unsigned char *)keyword, len, out, &out_len);
}

int DianaClient::GetStor()
{
    int ret = 0;
    ret += 16;
    for (const auto &itr : keywords_conuter)
    {
        ret += itr.first.size();
        ret += sizeof(itr.second);
    }

    return ret;
}