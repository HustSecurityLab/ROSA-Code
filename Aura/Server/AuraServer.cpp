#include "AuraServer.h"
#include <map>
#include <string>
#include <iostream>
#include <algorithm>

using namespace std;

void AuraServer::Setup()
{
    EDB.clear();
    Cache.clear();
}

void AuraServer::SaveCipher(const array<unsigned char, 32> &label, const array<unsigned char, 32> &tag,
                            const std::vector<array<unsigned char, 32>> &ciphers)
{
    EDB[label] = std::pair<array<unsigned char, 32>, vector<array<unsigned char, 32>>>(tag, ciphers);
}

void AuraServer::Search(std::vector<std::string> &srch_result, const array<unsigned char, 32> &trapdoor,
                        const array<unsigned char, 32> &cache_token, const std::vector<GGMNode> &nodes)
{
    map<long, array<unsigned char, 16>> keys;
    int counter = 0;
    string tmp_str;
    unsigned char buf[64], hash_buf[32], key_buf[64];
    vector<long> search_pos;
    vector<pair<array<unsigned char, 32>, string>> newind;
    vector<array<unsigned char, 32>> delind;
    array<unsigned char, 32> label = {};

    compute_leaf_keys(keys, nodes, GGMTree::get_level());
    while (true)
    {
        bool if_dec = false;
        string decrypted_id;
        hmac_digest(label.data(), (const unsigned char *)&counter, sizeof(int),
                    (const unsigned char *)trapdoor.data(), trapdoor.size());

        counter++;
        if (EDB.find(label) == EDB.end())
            break;
        search_pos = BloomFilter::get_index((unsigned char *)EDB[label].first.data());
        sort(search_pos.begin(), search_pos.end());
        for (int i = 0; i < min(search_pos.size(), EDB[label].second.size()); ++i)
        {
            if (keys.find(search_pos[i]) == keys.end())
                continue;
            if (decrypt_id(decrypted_id, (const unsigned char *)EDB[label].second[i].data(),
                           (const unsigned char *)keys[search_pos[i]].data()))
            {
                newind.emplace_back(pair<array<unsigned char, 32>, string>(EDB[label].first, decrypted_id));
                if_dec = true;
                break;
            }
        }
        if (!if_dec)
            delind.emplace_back(EDB[label].first);
    }
    for (auto &tag : delind)
        Cache[cache_token].erase(tag);
    for (auto &itr : newind)
        Cache[cache_token][itr.first] = itr.second;
    for (auto &itr : Cache[cache_token])
        srch_result.emplace_back(itr.second);
}

void AuraServer::compute_leaf_keys(map<long, array<unsigned char, 16>> &keys, const vector<GGMNode> &node_list, int level)
{
    for (GGMNode node : node_list)
    {
        for (int i = 0; i < pow(2, level - node.level); ++i)
        {
            int offset = ((node.index) << (level - node.level)) + i;
            uint8_t derive_key[AES_BLOCK_SIZE];
            memcpy(derive_key, node.key, AES_BLOCK_SIZE);
            GGMTree::derive_key_from_tree(derive_key, offset, 0, level - node.level);
            if (keys.find(offset) == keys.end())
            {
                array<unsigned char, 16> key_ = {};
                memcpy(key_.data(), derive_key, 16);
                keys[offset] = key_;
            }
        }
    }
}

void AuraServer::dump_data(const std::string &filename)
{
    size_t size, size1;
    FILE *f_out = fopen(filename.c_str(), "wb");

    size = EDB.size();
    fwrite(&size, sizeof(size), 1, f_out);
    for (auto &itr : EDB)
    {
        fwrite(itr.first.data(), sizeof(unsigned char), 32, f_out);
        fwrite(itr.second.first.data(), sizeof(unsigned char), 32, f_out);
        size1 = itr.second.second.size();
        fwrite(&size1, sizeof(size1), 1, f_out);
        for (int i = 0; i < size1; i++)
            fwrite(itr.second.second[i].data(), sizeof(unsigned char), 32, f_out);
    }

    size = Cache.size();
    fwrite(&size, sizeof(size), 1, f_out);
    for (auto &itr : Cache)
    {
        fwrite(itr.first.data(), sizeof(unsigned char), 32, f_out);
        size1 = itr.second.size();
        fwrite(&size1, sizeof(size1), 1, f_out);
        for (auto &itr1 : itr.second)
        {
            fwrite(itr1.first.data(), sizeof(unsigned char), 32, f_out);
            save_string(f_out, itr1.second);
        }
    }

    fclose(f_out);
}

void AuraServer::load_data(const std::string &filename)
{
    size_t size, size1;
    FILE *f_in = fopen(filename.c_str(), "rb");

    EDB.clear();
    Cache.clear();

    fread(&size, sizeof(size), 1, f_in);
    for (int i = 0; i < size; i++)
    {
        array<unsigned char, 32> tmp = {}, tmp1 = {}, tmp2 = {};
        vector<array<unsigned char, 32>> cip;

        fread(tmp.data(), sizeof(unsigned char), 32, f_in);
        fread(tmp1.data(), sizeof(unsigned char), 32, f_in);
        fread(&size1, sizeof(size), 1, f_in);
        for (int j = 0; j < size1; j++)
        {
            fread(tmp2.data(), sizeof(unsigned char), 32, f_in);
            cip.emplace_back(tmp2);
        }
        EDB[tmp] = pair<array<unsigned char, 32>, vector<array<unsigned char, 32>>>(tmp1, cip);
    }

    fread(&size, sizeof(size), 1, f_in);
    for (int i = 0; i < size; i++)
    {
        string str;
        array<unsigned char, 32> tmp1 = {}, tmp2 = {};
        fread(tmp1.data(), sizeof(unsigned char), 32, f_in);
        fread(&size1, sizeof(size1), 1, f_in);
        Cache[tmp1] = map<array<unsigned char, 32>, string>();
        for (int j = 0; j < size1; j++)
        {
            fread(tmp2.data(), sizeof(unsigned char), 32, f_in);
            load_string(str, f_in);
            Cache[tmp1][tmp2] = str;
        }
    }

    fclose(f_in);
}

void AuraServer::GetStor(int &EDB_stor, int &Cache_stor)
{
    EDB_stor = 0;
    Cache_stor = 0;

    for (const auto &itr : EDB)
    {
        EDB_stor += itr.first.size();
        EDB_stor += itr.second.first.size();
        for (const auto &itr1 : itr.second.second)
            EDB_stor += itr1.size();
    }

    for (const auto &itr : Cache)
    {
        Cache_stor += itr.first.size();
        for (const auto &itr1 : itr.second)
        {
            Cache_stor += itr1.first.size();
            Cache_stor += itr1.second.size();
        }
    }
}