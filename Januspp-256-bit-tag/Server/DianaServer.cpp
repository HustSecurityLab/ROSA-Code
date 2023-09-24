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

#include "DianaServer.h"

using std::map;
using std::string;
using std::cout;
using std::endl;

int DianaServer::Setup()
{
    cipher_store.clear();
    psk_store.clear();

    return 1;
}

int DianaServer::Save(const std::array<unsigned char, 32> &label, const DianaData &payload)
{
    cipher_store[label] = payload;

    return 1;
}

int DianaServer::Save(const std::array<unsigned char, 32> &label, const DianaDataDel &payload)
{
    psk_store[label] = payload;

    return 1;
}

int DianaServer::Search(ConstrainedKey &trpder_key, unsigned char *kw1, std::vector<DianaData> &out)
{
    unsigned char buf1[64];
    std::array<unsigned char, 32> _label={};
    ConstrainedPRF c_prf;

    for (unsigned int i = 0; i <= trpder_key.current_permitted; i++)
    {
        c_prf.Eval(trpder_key, i, buf1);

        memcpy(buf1 + 16, kw1, 16);
        SHA256(buf1, 32, _label.data());

        if (cipher_store.find(_label) != cipher_store.end())
        {
            out.emplace_back(cipher_store[_label]);
        }
        else
            return 0;
    }

    return 1;
}

int DianaServer::Search(ConstrainedKey &trpder_key, unsigned char *kw1, std::vector<DianaDataDel> &out)
{
    unsigned char buf1[64], buf2[32];
    std::array<unsigned char, 32> _label={};
    ConstrainedPRF c_prf;

    for (unsigned int i = 0; i <= trpder_key.current_permitted; i++)
    {
        c_prf.Eval(trpder_key, i, buf1);
        memcpy(buf1 + 16, kw1, 16);
        SHA256(buf1, 32, _label.data());
        if (psk_store.find(_label) != psk_store.end())
            out.emplace_back(psk_store[_label]);
        else
            return 0;
    }
    return 1;
}

void DianaServer::dump_data(FILE *f_out)
{
    unsigned long len_map, len_str;

    len_map = this->cipher_store.size();
    fwrite(&len_map, sizeof(char), sizeof(len_map), f_out);
    for (auto &itr: this->cipher_store)
    {
        len_str = itr.first.size();
        fwrite(&len_str, sizeof(char), sizeof(len_str), f_out);
        fwrite(itr.first.data(), sizeof(char), len_str, f_out);

        fwrite(itr.second.cip.data(), sizeof(char), 32, f_out);
        itr.second.tag.dump_data(f_out);
    }

    len_map = this->psk_store.size();
    fwrite(&len_map, sizeof(char), sizeof(len_map), f_out);
    for (auto &itr: this->psk_store)
    {
        len_str = itr.first.size();
        fwrite(&len_str, sizeof(char), sizeof(len_str), f_out);
        fwrite(itr.first.data(), sizeof(char), len_str, f_out);

        itr.second.key.dump_data(f_out);
        itr.second.tag.dump_data(f_out);
    }
}

void DianaServer::load_data(FILE *f_in)
{
    unsigned long len_map, len_str;
    char buf1[500];

    this->cipher_store.clear();
    this->psk_store.clear();

    fread(&len_map, sizeof(char), sizeof(len_map), f_in);
    for (unsigned long i = 0; i < len_map; i++)
    {
        std::array<unsigned char, 32> label = {};
        DianaData data;

        fread(&len_str, sizeof(char), sizeof(len_str), f_in);
        fread(label.data(), sizeof(char), len_str, f_in);

        fread(data.cip.data(), sizeof(char), 32, f_in);
        data.tag.load_data(f_in);

        this->cipher_store[label] = data;
    }

    fread(&len_map, sizeof(char), sizeof(len_map), f_in);
    for (unsigned long i = 0; i < len_map; i++)
    {
        std::array<unsigned char, 32> label={};
        DianaDataDel data;

        fread(&len_str, sizeof(char), sizeof(len_str), f_in);
        fread(label.data(), sizeof(char), len_str, f_in);

        data.key.load_data(f_in);
        data.tag.load_data(f_in);

        this->psk_store[label] = data;

    }
}

DianaServer::~DianaServer()
{

}

int DianaServer::GetStor()
{
    size_t ret = 0;

    for(const auto &itr:cipher_store)
    {
        ret += itr.first.size();
        ret += itr.second.cip.size();
        ret += itr.second.tag.size();
    }
    for(const auto &itr:psk_store)
    {
        ret += itr.first.size();
        ret += itr.second.tag.size();
        ret += itr.second.key.size();
    }
    return ((int) ret);
}