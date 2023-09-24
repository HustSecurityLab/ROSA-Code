#include "MitraServer.h"
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
}

using std::string;
using std::vector;
using std::list;
using std::set;


int MitraServer::Setup()
{
    this->cipher_db.clear();

    return 1;
}

int MitraServer::save(const std::array<unsigned char, 32> &label, const std::array<unsigned char, 32> &cipherr)
{
    this->cipher_db[label] = cipherr;

    return 1;
}

int MitraServer::search(std::vector<std::array<unsigned char, 32>> &Fw,
                        const std::vector<std::array<unsigned char, 32>> &tlist)
{
    for (const auto &a:tlist)
        Fw.emplace_back(this->cipher_db[a]);

    return 1;
}

void MitraServer::dump_data(const string &filename)
{
    FILE *f_out = fopen(filename.c_str(), "wb");
    unsigned long db_len = this->cipher_db.size();
    unsigned long str_len;

    fwrite(&db_len, sizeof(char), sizeof(db_len), f_out);

    for (auto &itr:this->cipher_db)
    {
        str_len = itr.first.size();
        fwrite(&str_len, sizeof(char), sizeof(str_len), f_out);
        fwrite(itr.first.data(), sizeof(char), str_len, f_out);

        str_len = itr.second.size();
        fwrite(&str_len, sizeof(char), sizeof(str_len), f_out);
        fwrite(itr.second.data(), sizeof(char), str_len, f_out);
    }

    fclose(f_out);
}

void MitraServer::load_data(const string &filename)
{
    FILE *f_in = fopen(filename.c_str(), "rb");
    unsigned long count;
    unsigned long str_len;

    this->cipher_db.clear();

    fread(&count, sizeof(char), sizeof(count), f_in);

    for (unsigned long i = 0; i < count; i++)
    {
        std::array<unsigned char, 32> l={},v={};

        fread(&str_len, sizeof(char), sizeof(str_len), f_in);
        fread(l.data(), sizeof(char), str_len, f_in);

        fread(&str_len, sizeof(char), sizeof(str_len), f_in);
        fread(v.data(), sizeof(char), str_len, f_in);

        this->cipher_db[l] = v;
    }

    fclose(f_in);
}

int MitraServer::GetStor()
{
    int ret = 0;

    for(const auto &itr:cipher_db)
    {
        ret += itr.first.size();
        ret += itr.second.size();
    }

    return ret;
}