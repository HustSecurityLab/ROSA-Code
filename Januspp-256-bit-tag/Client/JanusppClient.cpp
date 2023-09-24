#include <string>
#include <vector>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <iostream>

extern "C"
{
#include <openssl/sha.h>
#include <openssl/hmac.h>
}

#include "JanusppClient.h"

using namespace std;

int JanusPPClient::Setup()
{
    FILE *f_rand;

    f_rand = fopen("/dev/urandom", "rb");
    fread(ks, sizeof(unsigned char), 16, f_rand);
    fread(kt, sizeof(unsigned char), 16, f_rand);
    fclose(f_rand);

    this->deleting_support = MAX_DELETESUPPORT;
    this->sc.clear();
    this->del.clear();
    this->msk.clear();
    this->psk.clear();

    this->diana_clnt.Setup();
    this->diana_clnt_del.Setup();
    return 0;
}

PunTag JanusPPClient::generate_tag(const std::string &keyword, const std::string &ind)
{
    string data_to_hash;
    PunTag ret;

    this->_prf_f(keyword, ind, ret.get_data_ptr());

    return ret;
}

int JanusPPClient::Add(std::array<unsigned char, 32> &label, DianaData &payload, const std::string &keyword,
                       const std::string &ind)
{
    PunEncryption spe;
    char id_to_encrypt[68];//id is 64 bytes hexhash

    _init_keyword_state(keyword);

    PunEncryptionKey spe_key(this->deleting_support, this->msk[keyword].data());

    payload.tag = generate_tag(keyword, ind);
    memset(id_to_encrypt, 0, 68);
    strncpy((char *) id_to_encrypt, ind.c_str(), 68);
    id_to_encrypt[64] = '\0';
    spe.encrypt_with_low_storage(payload, ind, &spe_key);

    //generate ciphertext of Diana
    this->diana_clnt.update(label, keyword + ":" + to_string(this->sc[keyword]));

    return 1;
}

int JanusPPClient::_init_keyword_state(const std::string &keyword)
{
    if (this->msk.find(keyword) == this->msk.end())
    {
        std::array<unsigned char, 16> _msk = {};
        std::array<unsigned char, 16> _psk = {};
        RAND_bytes(_msk.data(), 16);
        _psk = _msk;
        this->msk[keyword] = _msk;
        this->psk[keyword] = _psk;
        this->sc[keyword] = 0;
        this->del[keyword] = deleting_support;
    }
    return 1;
}

int
JanusPPClient::Delete(std::array<unsigned char, 32> &label, DianaDataDel &payload, const std::string &keyword,
                      const std::string &ind)
{
    PunEncryption spe;
    unsigned char buf1[32];

    _init_keyword_state(keyword);
    if (this->del[keyword] <= 0)
        return 0;
    payload.tag = generate_tag(keyword, ind);
    spe.incremental_punc(this->psk[keyword].data(), payload.tag, &(payload.key), buf1);

    memcpy(this->psk[keyword].data(), buf1, 16);

    //generate ciphertext of Diana
    this->diana_clnt_del.update(label, keyword + ":" + to_string(this->sc[keyword]));

    this->del[keyword] = this->del[keyword] - 1;

    return 1;
}

int JanusPPClient::trapdoor(std::array<unsigned char, 16> &msk_out, std::array<unsigned char, 32> &tkn,
                            ConstrainedKey &trpd, std::array<unsigned char, 16> &kw1,
                            ConstrainedKey &trpd_del, std::array<unsigned char, 16> &kw1_del,
                            const std::string &keyword)
{
    unsigned int len;

    if (this->msk.find(keyword) == this->msk.end())
        return 0;

    msk_out = this->psk[keyword];

    this->diana_clnt.trapdoor(keyword + ":" + to_string(this->sc[keyword]), trpd, kw1.data());
    this->diana_clnt_del.trapdoor(keyword + ":" + to_string(this->sc[keyword]), trpd_del, kw1_del.data());

    this->del[keyword] = deleting_support;
    this->sc[keyword] = this->sc[keyword] + 1;
    RAND_bytes(this->msk[keyword].data(), 16);
    this->psk[keyword] = this->msk[keyword];

    HMAC(EVP_sha256(), ks, 16, (unsigned char *) keyword.c_str(),
         keyword.length(), tkn.data(), &len);

    return 1;
}

void JanusPPClient::dump_data(const string &filename)
{
    FILE *f_out = fopen(filename.c_str(), "wb");
    unsigned long len_map, len_str;
    int map_data;

    fwrite(this->kt, sizeof(char), 16, f_out);
    fwrite(this->ks, sizeof(char), 16, f_out);

    //sc
    len_map = this->sc.size();

    fwrite(&len_map, sizeof(char), sizeof(len_map), f_out);

    for (auto &itr: this->sc)
    {
        len_str = itr.first.size();
        map_data = itr.second;

        fwrite(&len_str, sizeof(char), sizeof(len_str), f_out);
        fwrite(itr.first.c_str(), sizeof(char), len_str, f_out);
        fwrite(&map_data, sizeof(char), sizeof(map_data), f_out);
    }

    //del
    len_map = this->del.size();

    fwrite(&len_map, sizeof(char), sizeof(len_map), f_out);

    for (auto &itr: this->del)
    {
        len_str = itr.first.size();
        map_data = itr.second;

        fwrite(&len_str, sizeof(char), sizeof(len_str), f_out);
        fwrite(itr.first.c_str(), sizeof(char), len_str, f_out);
        fwrite(&map_data, sizeof(char), sizeof(map_data), f_out);
    }

    //msk
    len_map = this->msk.size();

    fwrite(&len_map, sizeof(char), sizeof(len_map), f_out);

    for (auto &itr: this->msk)
    {
        len_str = itr.first.size();

        fwrite(&len_str, sizeof(char), sizeof(len_str), f_out);
        fwrite(itr.first.c_str(), sizeof(char), len_str, f_out);

        fwrite(itr.second.data(), sizeof(char), 16, f_out);
    }

    //psk
    len_map = this->psk.size();

    fwrite(&len_map, sizeof(char), sizeof(len_map), f_out);

    for (auto &itr: this->psk)
    {
        len_str = itr.first.size();

        fwrite(&len_str, sizeof(char), sizeof(len_str), f_out);
        fwrite(itr.first.c_str(), sizeof(char), len_str, f_out);

        fwrite(itr.second.data(), sizeof(char), 16, f_out);
    }

    fwrite(&(this->deleting_support), sizeof(char), sizeof(this->deleting_support), f_out);

    this->diana_clnt.dump_data(f_out);
    this->diana_clnt_del.dump_data(f_out);

    fclose(f_out);
}

void JanusPPClient::load_data(const std::string &filename)
{
    FILE *f_in = fopen(filename.c_str(), "rb");
    unsigned long len_map, len_str;
    char buf1[500];
    int map_data;

    this->sc.clear();
    this->del.clear();

    this->msk.clear();
    this->psk.clear();

    fread(this->kt, sizeof(char), 16, f_in);
    fread(this->ks, sizeof(char), 16, f_in);

    //sc
    fread(&len_map, sizeof(char), sizeof(len_map), f_in);

    for (unsigned long i = 0; i < len_map; i++)
    {
        string keyword;

        fread(&len_str, sizeof(char), sizeof(len_str), f_in);
        fread(buf1, sizeof(char), len_str, f_in);
        fread(&map_data, sizeof(char), sizeof(map_data), f_in);
        buf1[len_str] = 0;
        keyword = buf1;
        this->sc[keyword] = map_data;
    }

    //del
    fread(&len_map, sizeof(char), sizeof(len_map), f_in);

    for (unsigned long i = 0; i < len_map; i++)
    {
        string keyword;

        fread(&len_str, sizeof(char), sizeof(len_str), f_in);
        fread(buf1, sizeof(char), len_str, f_in);
        fread(&map_data, sizeof(char), sizeof(map_data), f_in);
        buf1[len_str] = 0;
        keyword = buf1;
        this->del[keyword] = map_data;
    }

    //msk
    fread(&len_map, sizeof(char), sizeof(len_map), f_in);

    for (unsigned long i = 0; i < len_map; i++)
    {
        string keyword;
        array<unsigned char, 16> data = {};
        fread(&len_str, sizeof(char), sizeof(len_str), f_in);
        fread(buf1, sizeof(char), len_str, f_in);
        fread(data.data(), sizeof(char), 16, f_in);

        buf1[len_str] = 0;
        keyword = buf1;
        this->msk[keyword] = data;
    }

    //psk
    fread(&len_map, sizeof(char), sizeof(len_map), f_in);

    for (unsigned long i = 0; i < len_map; i++)
    {
        string keyword;
        array<unsigned char, 16> data = {};

        fread(&len_str, sizeof(char), sizeof(len_str), f_in);
        fread(buf1, sizeof(char), len_str, f_in);
        fread(data.data(), sizeof(char), 16, f_in);

        buf1[len_str] = 0;
        keyword = buf1;
        this->psk[keyword] = data;
    }

    fread(&(this->deleting_support), sizeof(char), sizeof(this->deleting_support), f_in);

    this->diana_clnt.load_data(f_in);
    this->diana_clnt_del.load_data(f_in);

    fclose(f_in);
}

JanusPPClient::~JanusPPClient()
{

}

int JanusPPClient::_prf_f(const std::string &keyword, const std::string &ind, unsigned char *data)
{
    unsigned int out_len;
    string data_to_hmac = keyword + ":@:" + ind;
    HMAC(EVP_sha256(), this->kt, 16,
         (const unsigned char *) data_to_hmac.c_str(), data_to_hmac.length(), data, &out_len);


    return out_len;
}

int JanusPPClient::GetStor()
{
    int ret = 0;
    //kt and ks
    ret += 16;
    ret += 16;
    for(const auto &itr:sc)
    {
        ret += itr.first.size();
        ret += sizeof(itr.second);
    }
    for(const auto &itr:del)
    {
        ret += itr.first.size();
        ret += sizeof(itr.second);
    }
    for(const auto &itr:msk)
    {
        ret += itr.first.size();
        ret += itr.second.size();
    }
    for(const auto &itr:psk)
    {
        ret += itr.first.size();
        ret += itr.second.size();
    }
    ret += sizeof(deleting_support);
    ret += diana_clnt.GetStor();
    ret += diana_clnt_del.GetStor();

    return ret;
}