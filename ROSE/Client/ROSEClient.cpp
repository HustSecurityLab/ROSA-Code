#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <set>

extern "C"
{
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
}

#include <experimental/filesystem>
#include "ROSEClient.h"
#include "../CommonUtils.h"

using namespace std;

ROSEClient::ROSEClient()
{
    memset(this->Kse, 0, 16);
}

ROSEClient::~ROSEClient()
{
}


int ROSEClient::Setup()
{
    RAND_bytes(this->Kse, 16);

    return 0;
}

int ROSEClient::Update(string &L_out, string &cip_R, string &cip_D, string &cip_C, OP op,
                       const string &keyword, const string &ind)
{
    unsigned char buf1[256], buf2[256], buf_D[256], buf_K1[256], buf_S1[256], buf_R[256];
    OP op1;
    unsigned char op_ch;
    string s_K1, s_S1, s_R1, value;
    string id1;
    KUPRF kuprf;
    array<unsigned char, 32> _cip_C;

    if (op == op_add)
        op_ch = 0x0f;
    else if (op == op_del)
        op_ch = 0xf0;
    else
        op_ch = 0xff;

    if (this->LastK.find(keyword) == this->LastK.end())
    {
        RAND_bytes(buf_S1, 16);
        kuprf.key_gen(buf_K1);
        s_S1.assign((char *) buf_S1, 16);
        s_K1.assign((char *) buf_K1, 32);
        this->LastK[keyword] = s_K1;
        this->LastS[keyword] = s_S1;
    }
    else
    {
        s_K1 = this->LastK[keyword];
        s_S1 = this->LastS[keyword];
        memcpy(buf_K1, (const unsigned char *) s_K1.c_str(), 32);
        memcpy(buf_S1, (const unsigned char *) s_S1.c_str(), 16);
    }

    RAND_bytes(buf_R, 16);
    cip_R.assign((const char *) buf_R, 16);

    kuprf.Eval(buf2, buf_K1, keyword, ind, op);
    Hash_G(buf1, buf2, buf_R);

    L_out.assign((const char *) buf1, 32);

    Enc_id(_cip_C, ind);
    cip_C.assign((char *) _cip_C.data(), _cip_C.size());

    PRF_F(buf1, buf_S1, keyword, ind, op);
    Hash_H(buf_D, 1 + 32 * 2 + 33, buf1, buf_R);
    buf_D[0] = buf_D[0] ^ op_ch;

    if (this->LastOp.find(keyword) != this->LastOp.end())
    {
        id1 = this->LastId[keyword];
        op1 = this->LastOp[keyword];
        s_R1 = this->LastR[keyword];

        kuprf.Eval(buf1, buf_K1, keyword, id1, op1);
        Hash_G(buf2, buf1, (const unsigned char *) s_R1.c_str());
        Xor(32, buf_D + 1 + 33, buf2, buf_D + 1 + 33);

        PRF_F(buf1, buf_S1, keyword, id1, op1);
        Xor(32, buf_D + 1 + 33 + 32, buf1, buf_D + 1 + 33 + 32);

        if (op == op_del)
        {
            kuprf.Eval(buf1, buf_K1, keyword, ind, op_add);
            Xor(33, buf_D + 1, buf1, buf_D + 1);
        }
    }


    LastOp[keyword] = op;
    LastId[keyword] = ind;
    LastR[keyword] = cip_R;

    cip_D.assign((const char *) buf_D, 1 + 33 + 32 * 2);

    return 0;
}


int ROSEClient::Enc_id(array<unsigned char, 32> &C_out, const string &id)
{
    unsigned char IV[16], buf[128], plain[32];
    EVP_CIPHER_CTX *ctx;
    int len_out, len_out1;

    memset(plain, 0, 32);
    memset(buf, 0, 128);

    ctx = EVP_CIPHER_CTX_new();

    RAND_bytes(IV, 16);
    memcpy(buf, IV, 16);

    EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, Kse, IV);

    memcpy(plain, id.data(), id.size() > 12 ? 12 : id.size());
    plain[12] = 'c';
    plain[13] = '#';
    plain[14] = '*';
    plain[15] = '$';

    EVP_EncryptUpdate(ctx, buf + 16, &len_out, plain, 16);
    EVP_EncryptFinal_ex(ctx, buf + 16 + len_out, &len_out1);

    memcpy(C_out.data(), buf, 32);
    EVP_CIPHER_CTX_free(ctx);

    return 0;
}

int ROSEClient::Trapdoor(string &tpd_L, string &tpd_T, string &cip_L, string &cip_R,
                         string &cip_D, string &cip_C, const string &keyword)
{
    string s_R1, s_K1, s_S1, s_K, s_S;
    string s_id1, ind_0;
    OP op1;
    unsigned char buf1[256], buf2[256], buf_D[256], buf_R[256], buf_K1[256], buf_S1[256];
    unsigned char buf_K[256], buf_S[256];
    KUPRF kuprf;
    array<unsigned char, 32> _cip_C = {};

    ind_0 = "";

    s_id1 = this->LastId[keyword];
    op1 = this->LastOp[keyword];
    s_R1 = this->LastR[keyword];

    s_K1 = this->LastK[keyword];
    s_S1 = this->LastS[keyword];

    memcpy(buf_K1, (const unsigned char *) s_K1.c_str(), 32);
    memcpy(buf_S1, (const unsigned char *) s_S1.c_str(), 16);

    kuprf.Eval(buf1, buf_K1, keyword, s_id1, op1);
    Hash_G(buf2, buf1, (const unsigned char *) s_R1.c_str());

    memcpy(buf_D + 1 + 33, buf2, 32);
    tpd_L.assign((const char *) buf2, 32);

    PRF_F(buf1, buf_S1, keyword, s_id1, op1);
    memcpy(buf_D + 1 + 33 + 32, buf1, 32);
    tpd_T.assign((const char *) buf1, 32);

    kuprf.key_gen(buf_K);
    RAND_bytes(buf_S, 16);
    s_K.assign((const char *) buf_K, 32);
    s_S.assign((const char *) buf_S, 16);

    RAND_bytes(buf_R, 16);
    cip_R.assign((const char *) buf_R, 16);

    kuprf.update_token(buf_D + 1, buf_K, buf_K1);

    memset(buf1, 0, 64);
    kuprf.Eval(buf2, buf_K, keyword, ind_0, op_srh);
    Hash_G(buf1, buf2, buf_R);
    cip_L.assign((const char *) buf1, 32);

    PRF_F(buf1, buf_S, keyword, ind_0, op_srh);
    Hash_H(buf2, 1 + 32 * 2 + 33, buf1, buf_R);
    buf_D[0] = 0xff;
    Xor(1 + 32 * 2 + 33, buf_D, buf2, buf_D);

    Enc_id(_cip_C, ind_0);
    cip_C.assign((char *) _cip_C.data(), _cip_C.size());

    LastOp[keyword] = op_srh;
    LastId[keyword] = ind_0;
    LastR[keyword] = cip_R;

    LastK[keyword] = s_K;
    LastS[keyword] = s_S;

    cip_D.assign((const char *) buf_D, 1 + 32 * 2 + 33);

    return 0;
}


int ROSEClient::Decrypt(vector<string> &out, const string &keyword, const vector<array<unsigned char, 32>> &in)
{
    std::set<std::string> already_in_ret;

    if (in.empty())
    {
        this->LastOp.erase(keyword);
        this->LastK.erase(keyword);
        this->LastId.erase(keyword);
        this->LastR.erase(keyword);
        this->LastS.erase(keyword);
    }
    for (auto &itr: in)
    {
        string id;
        Dec_id(id, itr);
        if (already_in_ret.find(id) == already_in_ret.end())
        {
            already_in_ret.emplace(id);
            out.emplace_back(id);
        }
    }

    return 0;
}

int ROSEClient::Dec_id(string &id_out, const array<unsigned char, 32> &C_in)
{
    unsigned char IV[16], plain[64];
    EVP_CIPHER_CTX *ctx;
    int len_out, len_out1;

    memset(plain, 0, 32);

    ctx = EVP_CIPHER_CTX_new();
    memcpy(IV, C_in.data(), 16);
    EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), nullptr, Kse, IV);

    EVP_DecryptUpdate(ctx, plain, &len_out, C_in.data() + 16, 16);
    EVP_DecryptFinal_ex(ctx, plain + len_out, &len_out1);

    EVP_CIPHER_CTX_free(ctx);

    if (!((plain[12] == 'c') && (plain[13] == '#') && (plain[14] == '*') && (plain[15] == '$')))
        return -1;

    plain[12] = 0;

    id_out = (char *) plain;

    return 0;
}

void ROSEClient::save_data(const std::string &fname)
{
    FILE *f_out = fopen(fname.c_str(), "wb");

    size_t size;

    fwrite(this->Kse, sizeof(char), 16, f_out);

    size = this->LastK.size();
    fwrite(&size, sizeof(size), 1, f_out);
    for (auto &itr: this->LastK)
    {
        save_string(f_out, itr.first);
        save_string(f_out, itr.second);
    }

    size = this->LastS.size();
    fwrite(&size, sizeof(size), 1, f_out);
    for (auto &itr: this->LastS)
    {
        save_string(f_out, itr.first);
        save_string(f_out, itr.second);
    }

    size = this->LastR.size();
    fwrite(&size, sizeof(size), 1, f_out);
    for (auto &itr: this->LastR)
    {
        save_string(f_out, itr.first);
        save_string(f_out, itr.second);
    }

    size = this->LastId.size();
    fwrite(&size, sizeof(size), 1, f_out);
    for (auto &itr: this->LastId)
    {
        string id = itr.second;
        save_string(f_out, itr.first);
        save_string(f_out, id);
    }

    size = this->LastOp.size();
    fwrite(&size, sizeof(size), 1, f_out);
    for (auto &itr: this->LastOp)
    {
        save_string(f_out, itr.first);
        fwrite(&(itr.second), sizeof(itr.second), 1, f_out);
    }

    fclose(f_out);
}

void ROSEClient::load_data(const std::string &fname)
{
    FILE *f_in = fopen(fname.c_str(), "rb");

    size_t size;

    fread(this->Kse, sizeof(char), 16, f_in);

    fread(&size, sizeof(size), 1, f_in);
    this->LastK.clear();
    for (size_t i = 0; i < size; i++)
    {
        string str1, str2;
        str1 = load_string(f_in);
        str2 = load_string(f_in);
        this->LastK[str1] = str2;
    }

    fread(&size, sizeof(size), 1, f_in);
    this->LastS.clear();
    for (size_t i = 0; i < size; i++)
    {
        string str1, S;

        str1 = load_string(f_in);
        S = load_string(f_in);
        this->LastS[str1] = S;
    }

    fread(&size, sizeof(size), 1, f_in);
    this->LastR.clear();
    for (size_t i = 0; i < size; i++)
    {
        string str1, R;

        str1 = load_string(f_in);
        R = load_string(f_in);
        this->LastR[str1] = R;
    }

    fread(&size, sizeof(size), 1, f_in);
    this->LastId.clear();
    for (size_t i = 0; i < size; i++)
    {
        string str1, id;
        str1 = load_string(f_in);
        id = load_string(f_in);
        this->LastId[str1] = id;
    }

    fread(&size, sizeof(size), 1, f_in);
    this->LastOp.clear();
    for (size_t i = 0; i < size; i++)
    {
        string str1 = load_string(f_in);
        OP op;
        fread(&op, sizeof(op), 1, f_in);

        this->LastOp[str1] = op;
    }

    fclose(f_in);
}

int ROSEClient::GetStor()
{
    int ret = 0;
    //Kse
    ret += 16;
    for(const auto &itr:LastId)
    {
        ret += itr.first.size();
        ret += itr.second.size();
    }
    for(const auto &itr:LastK)
    {
        ret += itr.first.size();
        ret += itr.second.size();
    }
    for(const auto &itr:LastS)
    {
        ret += itr.first.size();
        ret += itr.second.size();
    }
    for(const auto &itr:LastR)
    {
        ret += itr.first.size();
        ret += itr.second.size();
    }
    for(const auto &itr:LastOp)
    {
        ret += itr.first.size();
        ret += sizeof(itr.second);
    }

    return ret;
}