#include "ROSAServer.h"
#include <map>
#include <string>
#include <iostream>
#include <algorithm>

using namespace std;

void ROSAServer::Setup()
{
    CDB.clear();
    Cache.clear();
}

void ROSAServer::SaveCipher(const std::array<unsigned char, 32> &label,
                            const std::vector<std::array<unsigned char, 32>> &ciphers)
{
    CDB[label] = ciphers;
}

void ROSAServer::Search(std::vector<std::string> &srch_result, const std::array<unsigned char, 32> &K_s,
                        int cnt_srch, int cnt_upd, const std::array<unsigned char, 32> &L_cache,
                        const std::vector<GGMNode> &nodes)
{
    map<long, std::array<unsigned char, 16>> keys;
    vector<long> search_pos;
    unsigned char buf[64], hash_buf[32], key_buf[64];
    string tag_str, plain;
    std::array<unsigned char, 32> label = {};

    if (Cache.find(L_cache) == Cache.end())
        Cache[L_cache] = map<string, string>{};
    map<string, string> &sCache = Cache[L_cache];

    compute_leaf_keys(keys, nodes, GGMTree::get_level());

    for (auto itr = sCache.begin(); itr != sCache.end(); itr++)
    {
        bool if_deleted = true;
        search_pos = BloomFilter::get_index((unsigned char *)itr->first.c_str());
        for (auto pos : search_pos)
            if (keys.find(pos) != keys.end())
            {
                if_deleted = false;
                break;
            }
        if (if_deleted)
            sCache.erase(itr++);
        else
            itr++;
    }

    memcpy(key_buf, K_s.data(), 32);

    for (int i = 0; i < cnt_upd; i++)
    {
        memcpy(key_buf + 32, &i, sizeof(int));
        SHA256(key_buf, 32 + sizeof(int), label.data());
        tag_str = to_string(cnt_srch) + "@" + to_string(i);
        SHA256((const unsigned char *)tag_str.c_str(), tag_str.length(), buf);
        // store the hash of tag in sCache
        tag_str.assign((char *)buf, 32);
        search_pos = BloomFilter::get_index(buf);
        sort(search_pos.begin(), search_pos.end());
        for (int j = 0; j < search_pos.size(); j++)
        {
            long index = search_pos[j];
            if (keys.find(search_pos[j]) == keys.end())
                continue;
            memcpy(key_buf + 32 + sizeof(int), &index, sizeof(index));
            sha3_digest(key_buf, 32 + sizeof(int) + sizeof(index), buf);
            for (int k = 0; k < 32; k++)
                buf[k] = buf[k] ^ CDB[label][j][k];
            /*cout << "---------------[" << search_pos[j] << "]-----------------" << endl;
            std::cout << "blook_key: ";
            print_hex(keys[search_pos[j]].c_str(), 16);
            std::cout << "ciphertext: ";
            print_hex(buf, 32);*/
            if (decrypt_id(plain, buf,
                           (const unsigned char *)keys[search_pos[j]].data()))
            {
                sCache[tag_str] = plain;
                break;
            }
        }
        CDB.erase(label);
    }
    for (auto &itr : sCache)
        srch_result.emplace_back(itr.second);
}

void ROSAServer::compute_leaf_keys(map<long, std::array<unsigned char, 16>> &keys,
                                   const vector<GGMNode> &node_list, int level)
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
                std::array<unsigned char, 16> key_ = {};

                memcpy(key_.data(), derive_key, 16);
                keys[offset] = key_;
            }
        }
    }
}

void ROSAServer::dump_data(const std::string &filename)
{
    size_t size, size1;
    string str;
    FILE *f_out = fopen((filename + "-srv").c_str(), "wb");

    size = CDB.size();
    fwrite(&size, sizeof(size), 1, f_out);
    for (auto &itr : CDB)
    {
        str.assign((char *)itr.first.data(), itr.first.size());
        save_string(f_out, str);
        size1 = itr.second.size();
        fwrite(&size1, sizeof(size1), 1, f_out);
        for (int i = 0; i < size1; i++)
        {
            str.assign((char *)itr.second[i].data(), itr.second[i].size());
            save_string(f_out, str);
        }
    }

    size = Cache.size();
    fwrite(&size, sizeof(size), 1, f_out);
    for (auto &itr : Cache)
    {
        str.assign((char *)itr.first.data(), itr.first.size());
        save_string(f_out, str);
        size1 = itr.second.size();
        fwrite(&size1, sizeof(size1), 1, f_out);
        for (auto &itr1 : itr.second)
        {
            save_string(f_out, itr1.first);
            save_string(f_out, itr1.second);
        }
    }

    fclose(f_out);
}

void ROSAServer::load_data(const std::string &filename)
{
    size_t size, size1;
    string str;
    FILE *f_in = fopen((filename + "-srv").c_str(), "rb");

    CDB.clear();
    Cache.clear();

    fread(&size, sizeof(size), 1, f_in);
    for (int i = 0; i < size; i++)
    {
        string tmp, tmp1;
        std::array<unsigned char, 32> l_ = {};
        vector<std::array<unsigned char, 32>> cip;

        load_string(tmp, f_in);
        fread(&size1, sizeof(size), 1, f_in);
        for (int j = 0; j < size1; j++)
        {
            std::array<unsigned char, 32> cip_ = {};

            load_string(tmp1, f_in);
            memcpy(cip_.data(), tmp1.c_str(), tmp1.length());
            cip.emplace_back(cip_);
        }
        memcpy(l_.data(), tmp.c_str(), tmp.length());
        CDB[l_] = cip;
    }

    fread(&size, sizeof(size), 1, f_in);
    for (int i = 0; i < size; i++)
    {
        std::array<unsigned char, 32> l_ = {};
        string str1, str2, str3;
        load_string(str1, f_in);
        memcpy(l_.data(), str1.c_str(), str1.length());
        fread(&size1, sizeof(size1), 1, f_in);
        Cache[l_] = map<string, string>();
        for (int j = 0; j < size1; j++)
        {
            load_string(str2, f_in);
            load_string(str3, f_in);
            Cache[l_][str2] = str3;
        }
    }

    fclose(f_in);
}

void ROSAServer::GetStor(int &CDB_stor, int &Cache_stor)
{
    CDB_stor = 0;
    Cache_stor = 0;

    for (const auto &itr : CDB)
    {
        CDB_stor += itr.first.size();
        for (const auto &itr1 : itr.second)
            CDB_stor += itr1.size();
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