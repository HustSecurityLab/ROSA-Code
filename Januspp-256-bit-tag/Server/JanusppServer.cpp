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

#include "JanusppServer.h"

using namespace std;

int JanusPPServer::Setup()
{
    diana_srv.Setup();
    diana_srv_del.Setup();
    OldRes.Setup();
    return 0;
}

int JanusPPServer::SaveCipher(const std::array<unsigned char, 32> &label, const DianaData &payload)
{
    return diana_srv.Save(label, payload);
}

int JanusPPServer::DeleteCipher(const std::array<unsigned char, 32> &label, const DianaDataDel &payload)
{
    return diana_srv_del.Save(label, payload);
}

int JanusPPServer::Search(std::vector<std::string> &output, std::array<unsigned char, 16> &msk_out,
                          std::array<unsigned char, 32> &tkn, ConstrainedKey &trpd, std::array<unsigned char, 16> &kw1,
                          ConstrainedKey &trpd_del, std::array<unsigned char, 16> &kw1_del)
{
    vector<DianaDataDel> srch_data_del;
    vector<DianaData> srch_data;
    PunEncryptionKey punc_key;
    PunEncryption punc_enc;
    map<array<unsigned char, 32>, string> NewR;
    string out_id;

    output.clear();

    diana_srv.Search(trpd, kw1.data(), srch_data);
    diana_srv_del.Search(trpd_del, kw1_del.data(), srch_data_del);

    punc_key.max_deletion = MAX_DELETESUPPORT;
    punc_key.current_deleted = srch_data_del.size();

    for (auto &_d : srch_data_del)
    {
        punc_key.key_data.emplace_back(_d.key);
    }
    if (punc_key.current_deleted < punc_key.max_deletion)
        punc_key.key_data.emplace_back(PuncturedKey(msk_out.data()));
    for (DianaData &c : srch_data)
    {
        if (punc_enc.decrypt(out_id, &punc_key, c))
        {
            std::array<unsigned char, 32> tag = {};
            memcpy(tag.data(), c.tag.get_data_ptr(), 32);
            NewR[tag] = out_id;
        }
    }
    for (auto &itr : srch_data_del)
    {
        std::array<unsigned char, 32> tag = {};
        memcpy(tag.data(), itr.tag.get_data_ptr(), 32);
        OldRes[tkn].erase(tag);
    }
    OldRes[tkn].insert(NewR.begin(), NewR.end());
    for (auto &itr : OldRes[tkn])
        output.emplace_back(itr.second);

    return 1;
}

void JanusPPServer::dump_data(const std::string &filename)
{
    FILE *f_out = fopen(filename.c_str(), "wb");
    unsigned int len_map, len_map_1;

    this->diana_srv.dump_data(f_out);
    this->diana_srv_del.dump_data(f_out);

    len_map = OldRes.size();

    fwrite(&len_map, sizeof(unsigned int), 1, f_out);
    for (auto &itr : OldRes)
    {
        fwrite(itr.first.data(), sizeof(unsigned char), itr.first.size(), f_out);
        len_map_1 = itr.second.size();
        fwrite(&len_map_1, sizeof(unsigned int), 1, f_out);
        for (auto &itr1 : itr.second)
        {
            unsigned int len_str = itr1.second.size();
            fwrite(itr1.first.data(), sizeof(unsigned char), itr1.first.size(), f_out);
            fwrite(&len_str, sizeof(unsigned int), 1, f_out);
            fwrite(itr1.second.c_str(), sizeof(char), len_str, f_out);
        }
    }

    fclose(f_out);
}

void JanusPPServer::load_data(const std::string &filename)
{
    FILE *f_in = fopen(filename.c_str(), "rb");
    unsigned int len_OldRes, len_submap;
    unsigned char buf[1024];

    OldRes.clear();
    this->diana_srv.load_data(f_in);
    this->diana_srv_del.load_data(f_in);

    fread(&len_OldRes, sizeof(unsigned int), 1, f_in);

    for (int i = 0; i < len_OldRes; i++)
    {
        std::array<unsigned char, 32> label;
        std::map<std::array<unsigned char, 32>, std::string> submap;

        fread(label.data(), sizeof(unsigned char), label.size(), f_in);
        fread(&len_submap, sizeof(unsigned int), 1, f_in);
        for (int j = 0; j < len_submap; j++)
        {
            std::array<unsigned char, 32> sublabel;
            unsigned int len_str;
            std::string val;

            fread(sublabel.data(), sizeof(unsigned char), sublabel.size(), f_in);
            fread(&len_str, sizeof(unsigned int), 1, f_in);
            fread(buf, sizeof(unsigned char), len_str, f_in);
            val.assign((char *)buf, len_str);
            submap[sublabel] = val;
        }
        OldRes[label] = submap;
    }

    fclose(f_in);
}

void JanusPPServer::GetStor(int &srv_stor, int &srv_del_stor, int &oldres_stor)
{
    srv_stor = srv_del_stor = oldres_stor = 0;

    for (const auto &itr : OldRes)
    {
        oldres_stor += itr.first.size();
        for (const auto &itr1 : itr.second)
        {
            oldres_stor += itr1.first.size();
            oldres_stor += itr1.second.size();
        }
    }

    srv_stor = diana_srv.GetStor();
    srv_del_stor = diana_srv_del.GetStor();
}