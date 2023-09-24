#include "ROSEServer.h"
#include <set>
#include <cstring>
#include <cstdlib>
#include <experimental/filesystem>
#include <thread>
#include <mutex>
#include <iostream>
#include <array>
#include <condition_variable>

extern "C"
{
#include "unistd.h"
}

using namespace std;

ROSEServer::~ROSEServer()
{
    for (auto itr : _store)
    {
        delete itr.second;
    }
    _store.clear();
}

int ROSEServer::Setup()
{
    for (auto itr : _store)
    {
        delete itr.second;
    }
    _store.clear();

    return 0;
}

int ROSEServer::Save(const string &L, const string &R, const string &D, const string &C)
{
    Cipher *cip = new Cipher;

    memcpy(cip->R, R.c_str(), 16);
    memcpy(cip->D, D.c_str(), 1 + 32 * 2 + 33);
    memcpy(cip->C, C.c_str(), 32);

    _store[L] = cip;

    return 0;
}

int ROSEServer::Search(vector<std::string> &result, const string &tpd_L, const string &tpd_T, const string &cip_L,
                       const string &cip_R, const string &cip_D, const string &cip_C)
{
    Cipher *cip = new Cipher;
    unsigned char buf1[256], buf2[256], buf3[256], buf_Dt[256], buf_Deltat[256];
    OP opt;
    vector<string> D;
    bool is_delta_null = true;
    string s_Lt, s_L1t, s_L1, s_T1, s_T1t, s_tmp;
    set<string> L_cache;
    KUPRF kuprf;

    memcpy(cip->R, cip_R.c_str(), 16);
    memcpy(cip->D, cip_D.c_str(), 1 + 33 + 32 * 2);
    memcpy(cip->C, cip_D.c_str(), 32);

    _store[cip_L] = cip;

    s_Lt = cip_L;
    memcpy(buf_Dt, cip_D.c_str(), 1 + 33 + 32 * 2);
    opt = op_srh;
    is_delta_null = true;

    s_L1 = s_L1t = tpd_L;
    s_T1 = s_T1t = tpd_T;

    while (true)
    {
        L_cache.emplace(s_L1);
        if (_store.find(s_L1) != _store.end())
            cip = _store[s_L1];
        else
        {
            L_cache.erase(s_L1);
            break;
        }
        Hash_H(buf2, 1 + 32 * 2 + 33, (const unsigned char *)s_T1.c_str(), cip->R);

        Xor(1 + 33 + 32 * 2, cip->D, buf2, buf3);
        if (buf3[0] == 0xf0) // del
        {
            L_cache.erase(s_L1);
            _store.erase(s_L1);
            delete cip;

            s_tmp.assign((const char *)buf3 + 1, 33);
            D.emplace_back(s_tmp);

            Xor(32, (const unsigned char *)s_L1t.c_str(), (const unsigned char *)buf3 + 1 + 33, buf2);
            Xor(32, (const unsigned char *)s_T1t.c_str(), (const unsigned char *)buf3 + 1 + 33 + 32,
                buf2 + 32);
            Xor(64, buf_Dt + 1 + 33, buf2, buf_Dt + 1 + 33);

            cip = _store[s_Lt];
            memcpy(cip->D, buf_Dt, 1 + 32 * 2 + 33);

            s_L1t.assign((const char *)buf3 + 1 + 33, 32);
            s_T1t.assign((const char *)buf3 + 1 + 33 + 32, 32);
        }
        else if (buf3[0] == 0x0f) // add
        {
            for (auto itr = D.rbegin(); itr != D.rend(); itr++)
            {
                Hash_G(buf1, (const unsigned char *)itr->c_str(), cip->R);
                if (memcmp(buf1, s_L1.c_str(), 32) == 0)
                {
                    L_cache.erase(s_L1);
                    _store.erase(s_L1);
                    delete cip;

                    Xor(32, (const unsigned char *)s_L1t.c_str(), (const unsigned char *)buf3 + 1 + 33, buf2);
                    Xor(32, (const unsigned char *)s_T1t.c_str(), (const unsigned char *)buf3 + 1 + 33 + 32,
                        buf2 + 32);
                    Xor(64, buf_Dt + 1 + 33, buf2, buf_Dt + 1 + 33);

                    cip = _store[s_Lt];
                    memcpy(cip->D, buf_Dt, 1 + 32 * 2 + 33);
                    s_L1t.assign((const char *)buf3 + 1 + 33, 32);
                    s_T1t.assign((const char *)buf3 + 1 + 33 + 32, 32);
                    cip = nullptr;
                    break;
                }
            }
            if (cip != nullptr)
            {
                s_Lt = s_L1;
                memcpy(buf_Dt, cip->D, 1 + 32 * 2 + 33);
                s_L1t.assign((const char *)buf3 + 1 + 33, 32);
                s_T1t.assign((const char *)buf3 + 1 + 33 + 32, 32);
                opt = op_add;
                s_tmp.assign((const char *)cip->C, 32);
                result.emplace_back(s_tmp);
            }
        }
        else
        {
            if (opt == op_srh && (!is_delta_null))
            {
                L_cache.erase(s_L1);
                _store.erase(s_L1);
                delete cip;

                kuprf.mul(buf1, buf_Deltat, buf3 + 1);

                Xor(32, buf_Deltat, buf1, buf_Deltat);
                Xor(32, buf_Dt + 1, buf_Deltat, buf_Dt + 1);

                Xor(32, (const unsigned char *)s_L1t.c_str(), buf3 + 1 + 33, buf2);
                Xor(32, (const unsigned char *)s_T1t.c_str(), buf3 + 1 + 33 + 32, buf2 + 32);
                Xor(64, buf_Dt + 1 + 33, buf2, buf_Dt + 1 + 33);

                cip = _store[s_Lt];
                memcpy(cip->D, buf_Dt, 1 + 32 * 2 + 33);

                memcpy(buf_Deltat, buf1, 32);
                s_L1t.assign((const char *)buf3 + 1 + 33, 32);
                s_T1t.assign((const char *)buf3 + 1 + 33 + 32, 32);
            }
            else
            {
                s_Lt = s_L1;
                memcpy(buf_Dt, cip->D, 1 + 32 * 2 + 33);
                s_L1t.assign((const char *)buf3 + 1 + 33, 32);
                s_T1t.assign((const char *)buf3 + 1 + 33 + 32, 32);
                opt = op_srh;
                memcpy(buf_Deltat, buf3 + 1, 32);
                is_delta_null = false;
            }
            for (auto itr = D.begin(); itr != D.end(); itr++)
            {
                kuprf.update(buf1, buf3 + 1, (const unsigned char *)itr->c_str());
                itr->assign((const char *)buf1, 33);
            }
        }
        memset(buf2, 0, 64);
        if (memcmp(buf2, buf3 + 1 + 33, 64) == 0)
            break;
        s_L1.assign((const char *)buf3 + 1 + 33, 32);
        s_T1.assign((const char *)buf3 + 1 + 33 + 32, 32);
    }
    if (result.empty())
    {
        for (auto itr = L_cache.begin(); itr != L_cache.end(); itr++)
        {
            Cipher *cip = _store[*itr];
            delete cip;
            _store.erase(*itr);
        }
    }
    return 0;
}

void ROSEServer::save_data(const std::string &fname)
{
    FILE *f_out = fopen(fname.c_str(), "wb");
    size_t size = this->_store.size();

    fwrite(&size, sizeof(size), 1, f_out);
    for (auto &itr : this->_store)
    {
        save_string(f_out, itr.first);
        fwrite(itr.second->R, sizeof(char), 16, f_out);
        fwrite(itr.second->D, sizeof(char), 1 + 32 * 2 + 33, f_out);
        fwrite(itr.second->C, sizeof(char), 32, f_out);
    }

    fclose(f_out);
}

void ROSEServer::load_data(const std::string &fname)
{
    FILE *f_in = fopen(fname.c_str(), "rb");
    size_t size;

    for (auto &itr : this->_store)
    {
        delete itr.second;
    }
    this->_store.clear();

    fread(&size, sizeof(size), 1, f_in);
    for (size_t i = 0; i < size; i++)
    {
        string str1 = load_string(f_in);
        auto cip = new Cipher;
        fread(cip->R, sizeof(char), 16, f_in);
        fread(cip->D, sizeof(char), 1 + 32 * 2 + 33, f_in);
        fread(cip->C, sizeof(char), 32, f_in);

        this->_store[str1] = cip;
    }
    fclose(f_in);
}

int ROSEServer::GetStor()
{
    int ret = 0;
    for (const auto &itr : _store)
    {
        ret += itr.first.size();
        // R + C + D
        ret += ((16) + (1 + 32 * 2 + 33) + (32));
    }
    return ret;
}