#include "MitraClient.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>
#include <vector>
#include <list>
#include <set>
#include <iostream>

extern "C"
{
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
}

using namespace std;

int MitraClient::Setup()
{
    RAND_bytes(this->k_master, 16);

    this->FileCnt.clear();

    return 1;
}

int MitraClient::update(std::array<unsigned char, 32> &label, std::array<unsigned char, 32> &cipher,
                        const std::string &keyword, const std::string &ind, OP op)
{
    char str[68];

    if (this->FileCnt.find(keyword) == this->FileCnt.end())
        this->FileCnt[keyword] = 0;

    this->FileCnt[keyword] = this->FileCnt[keyword] + 1;
    this->_prf_gen_label(keyword, this->FileCnt[keyword], label.data());
    this->_prf_gen_ciphertext(keyword, this->FileCnt[keyword], cipher.data());

    strncpy(str, ind.c_str(), 12);
    str[12] = '\0';

    for (int i = 0; i <= 12; i++)
        cipher[i] = cipher[i] ^ (unsigned char)str[i];

    if (op == op_add)
        cipher[13] = cipher[13] ^ 0xffu;
    else
        cipher[13] = cipher[13] ^ 0x00u;

    return 1;
}

int MitraClient::_prf_gen_label(const std::string &keyword, unsigned int c, unsigned char *label)
{
    unsigned int outlen;
    string data = keyword + "@" + to_string(c) + "@0";
    HMAC(EVP_sha256(), this->k_master, 16, (const unsigned char*)data.c_str(),data.length(), label, &outlen);
    return 1;
}

int MitraClient::_prf_gen_ciphertext(const std::string &keyword, unsigned int c, unsigned char *ciphertext)
{
    unsigned char buf[128];
    unsigned int tmp = 1;
    string hmacd_str = keyword + "@" + to_string(c) + "@1";

    HMAC(EVP_sha3_256(), this->k_master, 16, (const unsigned char*)hmacd_str.c_str(),
         hmacd_str.length(),ciphertext, &tmp);
    return 1;
}

int MitraClient::search_stage1(std::vector<std::array<unsigned char, 32>> &tlist, const std::string &keyword)
{
    std::array<unsigned char, 32> label = {};

    if (this->FileCnt.find(keyword) == this->FileCnt.end())
        this->FileCnt[keyword] = 0;

    for (unsigned int i = 1; i <= this->FileCnt[keyword]; i++)
    {
        string _t;
        this->_prf_gen_label(keyword, i, label.data());
        tlist.emplace_back(label);
    }

    return 1;
}

int MitraClient::search_stage2(std::vector<std::string> &search_ret, const std::string& keyword,
                               const std::vector<std::array<unsigned char, 32>> &Fw)
{
    unsigned char buf1[68], buf2[68];
    vector<string> _temp_ret;
    set<string> _id_to_del, already_in_ret;
    unsigned int counter = 1;

    _temp_ret.reserve(300000);

    for (const auto &a:Fw)
    {
        this->_prf_gen_ciphertext(keyword, counter, buf1);
        for (int i = 0; i <= 13; i++)
            buf2[i] = buf1[i] ^ (unsigned char) a[i];
        if (buf2[13] == 0xff)
            _temp_ret.emplace_back(string((char *) buf2));
        else
            _id_to_del.emplace(string((char *) buf2));
        counter++;
    }

    for (auto it = _temp_ret.begin(); it != _temp_ret.end(); it++)
    {
        if (_id_to_del.find(*it) == _id_to_del.end())
        {
            if(already_in_ret.find(*it) == already_in_ret.end())
            {
                already_in_ret.emplace(*it);
                search_ret.emplace_back(*it);
            }
        }
    }

    return 1;
}

void MitraClient::dump_data(const string &filename)
{
    FILE *f_out = fopen(filename.c_str(), "wb");
    unsigned long count_len = this->FileCnt.size();
    unsigned long str_len;
    unsigned int count;

    fwrite(this->k_master, sizeof(unsigned char), 16, f_out);
    fwrite(&count_len, sizeof(unsigned char), sizeof(count_len), f_out);

    for (auto &a:this->FileCnt)
    {
        str_len = a.first.size();
        count = a.second;

        fwrite(&str_len, sizeof(char), sizeof(str_len), f_out);
        fwrite(a.first.c_str(), sizeof(char), str_len, f_out);

        fwrite(&count, sizeof(char), sizeof(count), f_out);
    }

    fclose(f_out);
}

void MitraClient::load_data(const string &filename)
{
    FILE *f_in = fopen(filename.c_str(), "rb");
    unsigned long count_len;
    unsigned long str_len;
    unsigned int count;
    char buf1[512];

    this->FileCnt.clear();

    fread(this->k_master, sizeof(char), 16, f_in);
    fread(&count_len, sizeof(char), sizeof(count_len), f_in);

    for (unsigned long i = 0; i < count_len; i++)
    {
        string keyword;
        fread(&str_len, sizeof(char), sizeof(str_len), f_in);
        fread(buf1, sizeof(char), str_len, f_in);
        buf1[str_len] = 0;
        keyword = buf1;

        fread(&count, sizeof(char), sizeof(count), f_in);

        this->FileCnt[keyword] = count;
    }

    fclose(f_in);
}

int MitraClient::GetStor()
{
    int ret = 0;
    //k_master
    ret += 16;
    for(const auto &itr:FileCnt)
    {
        ret += itr.first.size();
        ret += sizeof(itr.second);
    }

    return ret;
}
