#include "ROSAClient.h"
#include <algorithm>
#include <chrono>
#include "../BF/BloomFilter.h"

extern "C"
{
#include <openssl/rand.h>
#include <openssl/sha.h>
}

using namespace std;

extern double bench_clnt_time;

ROSAClient::ROSAClient(int omap_cap, const std::string &srv_addr) : hirbTree(omap_cap, srv_addr, 12, 4096, 8)
{
    this->omap_cap = omap_cap;
    this->srv_addr = srv_addr;
    counter.clear();
    msk.clear();
    RAND_bytes(key, 16);
}

void ROSAClient::Update(std::array<unsigned char, 32> &label, std::vector<std::array<unsigned char, 32>> &cipher,
                        const std::string &keyword, const std::string &id, RosaOp op)
{
    unsigned char buf[128], derived_key[64], bloom_key[32], hash_buf[32];
    string omap_key, omap_val, str_tmp;
    int cnt_srch_old, cnt_upd_old, if_del;
    vector<long> bf_indexes;
    chrono::steady_clock::time_point begin, end;
    chrono::duration<double, std::micro> elapsed;

    //begin = chrono::steady_clock::now();

    cipher.clear();

    if (counter.find(keyword) == counter.end())
    {
        pair<int, int> cnt{0, 0};
        pair<std::array<unsigned char, 16>, bitset<GGM_SIZE>> sk;

        RAND_bytes(sk.first.data(), 16);
        sk.second.reset();

        counter[keyword] = cnt;
        msk[keyword] = sk;
    }

    omap_key = "@" + keyword + ":@-" + id;

    //end = chrono::steady_clock::now();
    //elapsed = end - begin;
    //bench_clnt_time += elapsed.count();

    hirbTree.get(omap_val, omap_key);

    //begin = chrono::steady_clock::now();
    if (op == RosaAdd)
    {
        if_del = 1;
        if (!omap_val.empty())
        {
            memcpy(&cnt_srch_old, omap_val.c_str(), sizeof(int));
            memcpy(&cnt_upd_old, omap_val.c_str() + sizeof(int), sizeof(int));
            memcpy(&if_del, omap_val.c_str() + 2 * sizeof(int), sizeof(int));
        }
        if (omap_val.empty() || if_del)
        {
            PRF_F(derived_key, key, keyword, counter[keyword].first);
            memcpy(derived_key + 32, &(counter[keyword].second), sizeof(int));
            SHA256(derived_key, 32 + sizeof(int), label.data());
            str_tmp = to_string(counter[keyword].first) + "@" + to_string(counter[keyword].second);
            SHA256((const unsigned char *)str_tmp.c_str(), str_tmp.length(), buf);
            bf_indexes = BloomFilter::get_index(buf);
            sort(bf_indexes.begin(), bf_indexes.end());
            for (int i = 0; i < bf_indexes.size(); i++)
            {
                array<unsigned char, 32> arr_tmp = {};
                long index = bf_indexes[i];
                memcpy(bloom_key, msk[keyword].first.data(), 16);
                GGMTree::derive_key_from_tree(bloom_key, index, 0);
                encrypt_id(arr_tmp.data(), id, bloom_key);
                memcpy(derived_key + 32 + sizeof(int), &index, sizeof(index));
                sha3_digest(derived_key, 32 + sizeof(int) + sizeof(index), hash_buf);
                for (int j = 0; j < 32; j++)
                    arr_tmp[j] = arr_tmp[j] ^ hash_buf[j];
                cipher.emplace_back(arr_tmp);
            }
            if_del = 0;
            memcpy(buf, &(counter[keyword].first), sizeof(int));
            memcpy(buf + sizeof(int), &(counter[keyword].second), sizeof(int));
            memcpy(buf + 2 * sizeof(int), &if_del, sizeof(int));
            omap_val.assign((char *)buf, 3 * sizeof(int));
            counter[keyword].second += 1;
        }
    }
    else
    {
        if_del = 1;
        if (!omap_val.empty())
        {
            memcpy(&cnt_srch_old, omap_val.c_str(), sizeof(int));
            memcpy(&cnt_upd_old, omap_val.c_str() + sizeof(int), sizeof(int));
            memcpy(&if_del, omap_val.c_str() + 2 * sizeof(int), sizeof(int));
        }
        if ((!omap_val.empty()) && (!if_del))
        {
            memset(buf, 0, 2 * sizeof(int));
            *((int *)(buf + 2 * sizeof(int))) = 1;
            omap_val.assign((char *)buf, 3 * sizeof(int));
            str_tmp = to_string(cnt_srch_old) + "@" + to_string(cnt_upd_old);
            SHA256((const unsigned char *)str_tmp.c_str(), str_tmp.length(), buf);
            BloomFilter::add_tag(msk[keyword].second, buf);
        }
    }
    if (omap_val.empty())
    {
        memset(buf, 0, 2 * sizeof(int));
        *((int *)(buf + 2 * sizeof(int))) = 1;
        omap_val.assign((char *)buf, 3 * sizeof(int));
    }
    //end = chrono::steady_clock::now();
    //elapsed = end - begin;
    //bench_clnt_time += elapsed.count();

    hirbTree.insert(omap_key, omap_val);
}

void ROSAClient::Trapdoor(std::array<unsigned char, 32> &K_s, int &cnt_srch, int &cnt_upd,
                          std::array<unsigned char, 32> &L_cache, std::vector<GGMNode> &nodes, const std::string &keyword)
{
    unsigned char buf[128], hash_buf[32];
    int int_tmp;
    vector<long> bf_pos, delete_pos, remain_pos;
    vector<GGMNode> nodes_, remain_node;

    if (counter.find(keyword) == counter.end())
    {
        cnt_srch = cnt_upd = 0;
        return;
    }
    cnt_srch = counter[keyword].first;
    cnt_upd = counter[keyword].second;
    counter[keyword].first += 1;
    counter[keyword].second = 0;

    int_tmp = keyword.length();
    if (int_tmp > 64)
        int_tmp = 64;
    memcpy(buf, key, 16);
    memcpy(buf + 16, keyword.c_str(), int_tmp);
    *((int *)(buf + 16 + int_tmp)) = -1;
    SHA256(buf, 16 + int_tmp + sizeof(int), L_cache.data());
    PRF_F(K_s.data(), key, keyword, cnt_srch);

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
}

int ROSAClient::bitset_to_bytes(unsigned char *out, const std::bitset<GGM_SIZE> &in)
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

int ROSAClient::biteset_from_bytes(std::bitset<GGM_SIZE> &out, const unsigned char *in)
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

void ROSAClient::dump_data(const std::string &filename)
{
    size_t size;
    unsigned char buf[GGM_SIZE / 8 + 1];
    FILE *f_out = fopen(filename.c_str(), "wb");

    fwrite(&(this->omap_cap), sizeof(int), 1, f_out);
    save_string(f_out, srv_addr);

    size = counter.size();
    fwrite(&size, sizeof(size), 1, f_out);
    for (auto &itr : counter)
    {
        save_string(f_out, itr.first);
        fwrite(&(itr.second.first), sizeof(itr.second.first), 1, f_out);
        fwrite(&(itr.second.second), sizeof(itr.second.second), 1, f_out);
    }

    size = msk.size();
    fwrite(&size, sizeof(size), 1, f_out);
    for (auto &itr : msk)
    {
        string str;
        save_string(f_out, itr.first);
        str.assign((char *)itr.second.first.data(), itr.second.first.size());
        save_string(f_out, str);
        bitset_to_bytes(buf, itr.second.second);
        fwrite(buf, sizeof(char), GGM_SIZE / 8 + 1, f_out);
    }

    fwrite(key, sizeof(char), 16, f_out);

    fclose(f_out);

    hirbTree.dump_data(filename + "-HIRB-tree");
}

void ROSAClient::load_data(const std::string &filename)
{
    size_t size;
    unsigned char buf[GGM_SIZE / 8 + 1];
    FILE *f_in = fopen(filename.c_str(), "rb");

    counter.clear();
    msk.clear();

    fread(&(this->omap_cap), sizeof(int), 1, f_in);
    load_string(srv_addr, f_in);

    fread(&size, sizeof(size), 1, f_in);
    for (int i = 0; i < size; i++)
    {
        string cnt_key;
        pair<int, int> cnt;

        load_string(cnt_key, f_in);
        fread(&(cnt.first), sizeof(cnt.first), 1, f_in);
        fread(&(cnt.second), sizeof(cnt.second), 1, f_in);
        counter[cnt_key] = cnt;
    }

    fread(&size, sizeof(size), 1, f_in);
    for (int i = 0; i < size; i++)
    {
        string msk_key, str;
        pair<std::array<unsigned char, 16>, bitset<GGM_SIZE>> msk_cell;

        load_string(msk_key, f_in);
        load_string(str, f_in);
        fread(buf, sizeof(char), GGM_SIZE / 8 + 1, f_in);
        biteset_from_bytes(msk_cell.second, buf);
        memcpy(msk_cell.first.data(), str.c_str(), 16);
        msk[msk_key] = msk_cell;
    }

    fread(key, sizeof(char), 16, f_in);
    fclose(f_in);
    hirbTree.load_data(filename + "-HIRB-tree");
}

void ROSAClient::Setup()
{
    counter.clear();
    msk.clear();
    RAND_bytes(key, 16);
}

int ROSAClient::GetStor()
{
    int ret = 0;

    //key
    ret += 16;
    ret += sizeof(omap_cap);
    ret += srv_addr.size();
    for (const auto &itr : counter)
    {
        ret += itr.first.size();
        ret += sizeof(itr.second.first);
        ret += sizeof(itr.second.second);
    }
    for (const auto &itr : msk)
    {
        ret += itr.first.size();
        ret += itr.second.first.size();
        ret += itr.second.second.size() / 8 + (itr.second.second.size() % 8 ? 1 : 0); // byte size
    }
    ret += hirbTree.GetStor();

    return ret;
}