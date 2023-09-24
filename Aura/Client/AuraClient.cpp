#include "AuraClient.h"
#include <algorithm>
#include <iostream>
#include "../BF/BloomFilter.h"

extern "C"
{
#include <openssl/rand.h>
#include <openssl/sha.h>
}

using namespace std;

AuraClient::AuraClient()
{
    counter.clear();
    msk.clear();
    RAND_bytes(Kt, 16);
}

void AuraClient::Update(array<unsigned char, 32> &label, array<unsigned char, 32> &tag, std::vector<array<unsigned char, 32>> &cipher,
                        const std::string &keyword, const std::string &id, OP op)
{
    string str_tmp;
    unsigned char buf[128], hash_buf[32];

    cipher.clear();

    str_tmp.assign((char *)Kt, 16);
    str_tmp += "@" + keyword + "@" + id;
    SHA256((const unsigned char *)str_tmp.c_str(), str_tmp.length(), tag.data());

    if (msk.find(keyword) == msk.end())
    {
        counter[keyword] = 0;
        pair<array<unsigned char, 16>, bitset<GGM_SIZE>> sk;

        RAND_bytes(sk.first.data(), 16);
        sk.second.reset();
        msk[keyword] = sk;
    }

    if (op == op_add)
    {
        vector<long> indexes = BloomFilter::get_index(tag.data());
        sort(indexes.begin(), indexes.end());
        for (long index : indexes)
        {
            unsigned char derived_key[64];
            array<unsigned char, 32> cip = {};

            memcpy(derived_key, msk[keyword].first.data(), 16);
            GGMTree::derive_key_from_tree(derived_key, index, 0);
            encrypt_id(cip.data(), id, derived_key);
            cipher.emplace_back(cip);
        }

        hmac_digest(buf, (const unsigned char *)keyword.c_str(), keyword.length(),
                    (const unsigned char *)msk[keyword].first.data(),
                    msk[keyword].first.size());
        hmac_digest(label.data(), (const unsigned char *)&(counter[keyword]), sizeof(int),
                    buf, 32);

        counter[keyword]++;
    }
    else
    {
        BloomFilter::add_tag(msk[keyword].second, tag.data());
    }
}

void AuraClient::Trapdoor(array<unsigned char, 32> &trapdoor, array<unsigned char, 32> &cache_token,
                          std::vector<GGMNode> &nodes, const std::string &keyword)
{
    unsigned char buf[128], hash_buf[32];
    int int_tmp;
    vector<long> bf_pos, delete_pos, remain_pos;
    vector<GGMNode> nodes_, remain_node;
    string str_tmp;

    if (counter.find(keyword) == counter.end())
    {
        trapdoor.fill(0);
        return;
    }

    str_tmp.assign((char *)Kt, 16);
    str_tmp += "@" + keyword;
    SHA256((const unsigned char *)str_tmp.c_str(), str_tmp.length(), cache_token.data());

    hmac_digest(trapdoor.data(), (const unsigned char *)keyword.c_str(), keyword.length(),
                (const unsigned char *)msk[keyword].first.data(),
                msk[keyword].first.size());

    for (int i = 0; i < GGM_SIZE; i++)
        bf_pos.emplace_back(i);
    delete_pos = BloomFilter::search(msk[keyword].second);
    set_difference(bf_pos.begin(), bf_pos.end(),
                   delete_pos.begin(), delete_pos.end(),
                   inserter(remain_pos, remain_pos.begin()));
    nodes_.reserve(remain_pos.size());
    for (long pos : remain_pos)
        nodes_.emplace_back(GGMNode(pos, GGMTree::get_level()));

    remain_node = GGMTree::min_coverage(nodes_);
    nodes.reserve(remain_node.size());
    for (auto &i : remain_node)
    {
        memcpy(i.key, msk[keyword].first.data(), 16);
        GGMTree::derive_key_from_tree(i.key, i.index, 0, i.level);
        GGMNode n(i.index, i.level);

        memcpy(n.key, i.key, 16);
        nodes.emplace_back(n);
    }
    counter[keyword] = 0;
    RAND_bytes(msk[keyword].first.data(), 16);
    msk[keyword].second.reset();
}

int AuraClient::bitset_to_bytes(unsigned char *out, const std::bitset<GGM_SIZE> &in)
{
    int bytes_len = in.size() / 8;

    if (in.size() % 8)
        bytes_len += 1;

    for (unsigned int i = 0; i < bytes_len; i++)
    {
        unsigned char tmp = 0;
        for (unsigned int j = i * 8; j < (i + 1) * 8; j++)
        {
            tmp = tmp << 1;
            if (j >= in.size())
                break;
            if (in[j])
                tmp = tmp + 1;
        }
        out[i] = tmp;
    }

    return bytes_len;
}

int AuraClient::biteset_from_bytes(std::bitset<GGM_SIZE> &out, const unsigned char *in)
{
    int bytes_len = out.size() / 8;

    if (out.size() % 8)
        bytes_len += 1;

    for (unsigned int i = 0; i < bytes_len; i++)
    {
        unsigned char tmp = 1u << 7u;
        for (unsigned int j = i * 8; j < (i + 1) * 8; j++)
        {
            if (j >= out.size())
                break;
            if (tmp & in[i])
                out[j] = true;
            else
                out[j] = false;
            tmp = tmp >> 1u;
        }
    }

    return bytes_len;
}

void AuraClient::dump_data(const std::string &filename)
{
    size_t size;
    unsigned char buf[GGM_SIZE / 8 + 1];
    FILE *f_out = fopen(filename.c_str(), "wb");

    size = counter.size();
    fwrite(&size, sizeof(size), 1, f_out);
    for (auto &itr : counter)
    {
        save_string(f_out, itr.first);
        fwrite(&(itr.second), sizeof(itr.second), 1, f_out);
    }

    size = msk.size();
    fwrite(&size, sizeof(size), 1, f_out);
    for (auto &itr : msk)
    {
        save_string(f_out, itr.first);
        fwrite(itr.second.first.data(), sizeof(unsigned char), itr.second.first.size(), f_out);
        bitset_to_bytes(buf, itr.second.second);
        fwrite(buf, sizeof(char), GGM_SIZE / 8 + 1, f_out);
    }

    fwrite(Kt, sizeof(char), 16, f_out);

    fclose(f_out);
}

void AuraClient::load_data(const std::string &filename)
{
    size_t size;
    unsigned char buf[GGM_SIZE / 8 + 1];
    FILE *f_in = fopen(filename.c_str(), "rb");

    counter.clear();
    msk.clear();

    fread(&size, sizeof(size), 1, f_in);
    for (int i = 0; i < size; i++)
    {
        string cnt_key;
        int cnt;

        load_string(cnt_key, f_in);
        fread(&(cnt), sizeof(cnt), 1, f_in);
        counter[cnt_key] = cnt;
    }

    fread(&size, sizeof(size), 1, f_in);
    for (int i = 0; i < size; i++)
    {
        string msk_key;
        pair<array<unsigned char, 16>, bitset<GGM_SIZE>> msk_cell;

        load_string(msk_key, f_in);
        fread(msk_cell.first.data(), sizeof(unsigned char), 16, f_in);
        fread(buf, sizeof(char), GGM_SIZE / 8 + 1, f_in);
        biteset_from_bytes(msk_cell.second, buf);
        msk[msk_key] = msk_cell;
    }

    fread(Kt, sizeof(char), 16, f_in);

    fclose(f_in);
}

void AuraClient::Setup()
{
    counter.clear();
    msk.clear();
    RAND_bytes(Kt, 16);
}

int AuraClient::GetStor()
{
    int ret = 0;

    ret = 16; // key size
    for (const auto &itr : counter)
    {
        ret += itr.first.size();
        ret += sizeof(itr.second);
    }
    for (const auto &itr : msk)
    {
        ret += itr.first.size();
        ret += itr.second.first.size();
        ret += itr.second.second.size() / 8 + (itr.second.second.size() % 8 ? 1 : 0); // byte size
    }

    return ret;
}