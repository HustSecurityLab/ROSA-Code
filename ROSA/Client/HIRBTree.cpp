#include "HIRBTree.h"
#include "vORAMClient.h"
#include <cmath>
#include <string>
#include <iostream>
#include "../CommonUtils.h"
#include <grpc/grpc.h>
#include <grpcpp/create_channel.h>
#include <chrono>

extern "C"
{
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <stdio.h>
}

using namespace std;

extern double bench_clnt_time;

HIRBTree::HIRBTree(int items_limit, const std::string &addr, int value_size, int bucket_size,
                   int size_factor) : SIZE_FACTOR(size_factor), height(0), size(0)
{
    int idlen_try;
    int initial_height;

    this->items_limit = items_limit;
    this->value_size = value_size;
    this->nodesize = bucket_size;

    this->keylen = 16;
    this->lenlen = (log2((this->nodesize - 2.0 * this->keylen - 2)) + 7) / 8;
    this->hashlen = 20;

    B = 1;
    LeafB = 1;
    while (1)
    {
        int B_try, LeafB_try;
        blobs_limit = ceil(items_limit * ((LeafB - 1.0) / (LeafB * LeafB) + 1.0 / (B * LeafB)));
        idlen_try = estimate_idlen(blobs_limit);
        estimate_B(B_try, LeafB_try, nodesize, idlen_try, keylen, lenlen, hashlen, value_size);
        if (LeafB_try <= LeafB)
            break;
        B = B_try;
        LeafB = LeafB_try;
    }

    if (B == 1)
        height = voram_clog(items_limit / LeafB, 2) + 1;
    else
        height = voram_clog(items_limit, B);

    estimate_B(B, LeafB, nodesize, idlen_try, keylen, lenlen, hashlen, ceil(value_size));

    RAND_bytes(salt, 16);

    this->addr = addr;

    shared_ptr<grpc::Channel> channel = grpc::CreateCustomChannel(addr,
                                                                  grpc::InsecureChannelCredentials(),
                                                                  get_channel_args());
    vORAM.Setup(nodesize, blobs_limit, idlen_try, keylen, channel, addr);

    root_id = "";
    hirbinit();
}

void HIRBTree::estimate_B(int &B_out, int &LeafB_out, int nodesize,
                          int idlen, int keylen, int lenlen, int hashlen, int valsize)
{
    int node_data = nodesize - 2 * keylen;
    int chunk_header = idlen + lenlen;

    B_out = ((node_data - SIZE_FACTOR * (chunk_header + idlen)) / (SIZE_FACTOR * (idlen + hashlen + valsize)));

    LeafB_out = ((node_data - SIZE_FACTOR * chunk_header) / (SIZE_FACTOR * (hashlen + valsize)));
}

void HIRBTree::hirbinit()
{
    string root_id;

    for (int i = height; i >= 0; i--)
    {
        HIRBTreeNode node;
        string str_tmp;

        if (i == height)
            node.if_leaf = true;
        else
        {
            node.if_leaf = false;
            node.children.emplace_back(root_id);
        }
        node.to_string(str_tmp);
        vORAM.insert(root_id, (unsigned char *) str_tmp.c_str(), str_tmp.length());
    }
    this->root_id = root_id;
    vORAM.finalize();
}

int HIRBTree::get_height(const unsigned char *label_hash, int hash_len)
{
    string tmp_str;
    unsigned char buf1[64], buf2[64], IV[16];
    int len_out, len_out1, height = 1;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    memset(IV, 0, 16);
    memset(buf1, 0, 64);
    memset(buf2, 0, 64);
    if (hash_len > 48)
        hash_len = 48;
    memcpy(buf1, label_hash, hash_len);

    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, salt, IV);

    if (this->height == 0)
        height = 0;
    else
    {
        EVP_EncryptUpdate(ctx, buf2, &len_out, buf1, hash_len);
        if ((*((int *) buf2) % this->LeafB) != 0)
            height = 0;
        else
            while (1)
            {
                if (height >= this->height)
                    break;
                EVP_EncryptUpdate(ctx, buf2, &len_out, buf1, hash_len);
                if ((*((int *) buf2) % this->B) != 0)
                    break;
                height++;
                memcpy(buf1, buf2, hash_len);
            }
    }

    EVP_EncryptFinal_ex(ctx, buf2, &len_out);
    EVP_CIPHER_CTX_free(ctx);
    return this->height - height;
}

void HIRBTree::HIRBpath_init(const std::string &label_hash)
{
    HIRB_path_stat.setup(this->height);

    HIRB_path_stat.id0 = root_id;
    vORAM.idgen(HIRB_path_stat.id0p);
    root_id = HIRB_path_stat.id0p;
    vORAM.idgen(HIRB_path_stat.id1);
    vORAM.idgen(HIRB_path_stat.id1p);
    HIRB_path_stat.found = false;
    HIRB_path_stat.l = -1;
    HIRB_path_stat.label_hash = label_hash;
}

bool HIRBTree::HIRBpath_proceed()
{
    chrono::steady_clock::time_point begin, end;
    chrono::duration<double, std::micro> elapsed;

    auto &v0 = HIRB_path_stat.v0;
    auto &v1 = HIRB_path_stat.v1;

    HIRB_path_stat.l++;
    if (HIRB_path_stat.l > height)
        return false;

    vORAM.batch_evict(HIRB_path_stat.id0, HIRB_path_stat.id1);

    //begin = chrono::steady_clock::now();
    if (HIRB_path_stat.l == height)
    {
        HIRB_path_stat.cid0p = "";
        HIRB_path_stat.cid1p = "";
    }
    else
    {
        vORAM.idgen(HIRB_path_stat.cid0p);
        vORAM.idgen(HIRB_path_stat.cid1p);
    }

    if (vORAM.stash.find(HIRB_path_stat.id0) != vORAM.stash.end())
    {
        v0.from_string(vORAM.stash[HIRB_path_stat.id0]);
    }
    else
    {
        string tmp;
        v0.clear();
        vORAM.idgen(tmp);
        v0.children.emplace_back(tmp);
    }
    vORAM.stash.erase(HIRB_path_stat.id0);

    if (HIRB_path_stat.found)
    {
        if (vORAM.stash.find(HIRB_path_stat.id1) != vORAM.stash.end())
        {
            v1.from_string(vORAM.stash[HIRB_path_stat.id1]);
        }
        else
        {
            string tmp;
            v1.clear();
            vORAM.idgen(tmp);
            v1.children.emplace_back(tmp);
        }
        vORAM.stash.erase(HIRB_path_stat.id1);

        if (HIRB_path_stat.l != height)
        {
            if (!v0.children.empty())
            {
                HIRB_path_stat.cid0 = v0.children.back();
                v0.children.back() = HIRB_path_stat.cid0p;
            }

            if (!v1.children.empty())
            {
                HIRB_path_stat.cid1 = v1.children.front();
                v1.children.front() = HIRB_path_stat.cid1p;
            }
        }
    }
    else
    {
        v1.clear();
        auto p_hash = v0.lhash.begin();
        auto p_children = v0.children.begin();

        while (p_hash != v0.lhash.end())
        {
            if (HIRB_path_stat.label_hash <= *p_hash)
                break;
            p_hash++;
            p_children++;
        }

        if (HIRB_path_stat.l != height)
        {
            HIRB_path_stat.cid0 = *p_children;
            *p_children = HIRB_path_stat.cid0p;
        }
        if (*p_hash == HIRB_path_stat.label_hash)
        {
            HIRB_path_stat.found = true;
            if (HIRB_path_stat.l != height)
            {
                p_children++;
                if (p_children != v0.children.end())
                {
                    HIRB_path_stat.cid1 = *p_children;
                    *p_children = HIRB_path_stat.cid1p;
                }
                else
                    vORAM.idgen(HIRB_path_stat.cid1);
            }
        }
        else
            vORAM.idgen(HIRB_path_stat.cid1);
    }
    //end = chrono::steady_clock::now();
    //elapsed = end - begin;
    //bench_clnt_time += elapsed.count();
    return true;
}

void HIRBTree::HIRBpath_finalize()
{
    vORAM.finalize();
}

void HIRBTree::insert(const string &label, const string &value)
{
    chrono::steady_clock::time_point begin, end;
    chrono::duration<double, std::micro> elapsed;

    unsigned char buf[32];
    string label_hash, str_tmp;
    int label_height;
    auto &v0 = HIRB_path_stat.v0;
    auto &v1 = HIRB_path_stat.v1;

    //begin = chrono::steady_clock::now();
    if (value.length() > value_size)
    {
        cerr << "HIRBTree Insert: value size " << value.length() << " longer than "
             << value_size << endl;
        return;
    }

    SHA1((const unsigned char *) label.c_str(), label.length(), buf);
    label_hash.assign((const char *) buf, 20);
    label_height = get_height(buf, 20);

    HIRBpath_init(label_hash);
    //end = chrono::steady_clock::now();
    //elapsed = end - begin;
    //bench_clnt_time += elapsed.count();

    while (HIRBpath_proceed())
    {
        //begin = chrono::steady_clock::now();
        auto p_value = v0.values.begin();
        auto p_children = v0.children.begin();
        auto p_hash = v0.lhash.begin();

        if (HIRB_path_stat.l != height)
            p_children++;
        while (p_hash != v0.lhash.end())
        {
            if (label_hash <= *p_hash)
                break;
            p_hash++;
            p_value++;
            if (HIRB_path_stat.l != height)
                p_children++;
        }
        if (*p_hash == label_hash)
            *p_value = value;
        else if (HIRB_path_stat.l == label_height)
        {
            if (HIRB_path_stat.l != height)
                v0.children.insert(p_children, HIRB_path_stat.cid1p);
            v0.lhash.insert(p_hash, label_hash);
            v0.values.insert(p_value, value);
        }
        else if ((!HIRB_path_stat.found) && (HIRB_path_stat.l > label_height) && (v1.children.empty()))
        {
            if (HIRB_path_stat.l == height)
                v1.if_leaf = true;
            else
                v1.children.emplace_back(HIRB_path_stat.cid1p);

            for (auto itr = p_hash; itr != v0.lhash.end(); itr++)
                v1.lhash.emplace_back(*itr);
            for (auto itr = p_value; itr != v0.values.end(); itr++)
                v1.values.emplace_back(*itr);
            if (!v1.if_leaf)
                for (auto itr = p_children; itr != v0.children.end(); itr++)
                    v1.children.emplace_back(*itr);

            v0.lhash.erase(p_hash, v0.lhash.end());
            v0.values.erase(p_value, v0.values.end());
            if (!v0.if_leaf)
                v0.children.erase(p_children, v0.children.end());
        }

        if (HIRB_path_stat.l == height)
            v0.if_leaf = true;
        v0.to_string(str_tmp);

        vORAM.stash[HIRB_path_stat.id0p] = str_tmp;
        if ((!v1.children.empty()) || v1.if_leaf)
        {
            v1.to_string(str_tmp);
            vORAM.stash[HIRB_path_stat.id1p] = str_tmp;
        }
        vORAM.writeback(HIRB_path_stat.id0);
        vORAM.writeback(HIRB_path_stat.id1);
        HIRB_path_stat.id0 = HIRB_path_stat.cid0;
        HIRB_path_stat.id0p = HIRB_path_stat.cid0p;
        HIRB_path_stat.id1 = HIRB_path_stat.cid1;
        HIRB_path_stat.id1p = HIRB_path_stat.cid1p;

        //end = chrono::steady_clock::now();
        //elapsed = end - begin;
        //bench_clnt_time += elapsed.count();
    }

    HIRBpath_finalize();
}

void HIRBTree::get(std::string &val_out, const string &label)
{
    chrono::steady_clock::time_point begin, end;
    chrono::duration<double, std::micro> elapsed;

    unsigned char buf[32];
    string label_hash, str_tmp;
    int label_height;
    auto &v0 = HIRB_path_stat.v0;
    auto &v1 = HIRB_path_stat.v1;

    //begin = chrono::steady_clock::now();
    val_out = "";

    SHA1((const unsigned char *) label.c_str(), label.length(), buf);
    label_hash.assign((const char *) buf, 20);
    label_height = get_height(buf, 20);

    HIRBpath_init(label_hash);

    //end = chrono::steady_clock::now();
    //elapsed = end - begin;
   // bench_clnt_time += elapsed.count();

    while (HIRBpath_proceed())
    {
        //begin = chrono::steady_clock::now();
        auto p_value = v0.values.begin();
        auto p_hash = v0.lhash.begin();

        while (p_hash != v0.lhash.end())
        {
            if (label_hash <= *p_hash)
                break;
            p_hash++;
            p_value++;
        }

        if (*p_hash == label_hash)
            val_out = *p_value;

        v0.to_string(str_tmp);

        vORAM.stash[HIRB_path_stat.id0p] = str_tmp;
        if ((!v1.children.empty()) || v1.if_leaf)
        {
            v1.to_string(str_tmp);
            vORAM.stash[HIRB_path_stat.id1p] = str_tmp;
        }
        vORAM.writeback(HIRB_path_stat.id0);
        vORAM.writeback(HIRB_path_stat.id1);
        HIRB_path_stat.id0 = HIRB_path_stat.cid0;
        HIRB_path_stat.id0p = HIRB_path_stat.cid0p;
        HIRB_path_stat.id1 = HIRB_path_stat.cid1;
        HIRB_path_stat.id1p = HIRB_path_stat.cid1p;
        //end = chrono::steady_clock::now();
        //elapsed = end - begin;
        //bench_clnt_time += elapsed.count();
    }

    HIRBpath_finalize();
}

void HIRBTree::dump_data(const std::string &filename)
{
    FILE *f_out = fopen(filename.c_str(), "wb");

    fwrite(&SIZE_FACTOR, sizeof(SIZE_FACTOR), 1, f_out);
    fwrite(&B, sizeof(B), 1, f_out);
    fwrite(&LeafB, sizeof(LeafB), 1, f_out);
    fwrite(&keylen, sizeof(keylen), 1, f_out);
    fwrite(&lenlen, sizeof(lenlen), 1, f_out);
    fwrite(&hashlen, sizeof(hashlen), 1, f_out);
    fwrite(&items_limit, sizeof(items_limit), 1, f_out);
    fwrite(&value_size, sizeof(value_size), 1, f_out);
    fwrite(&nodesize, sizeof(nodesize), 1, f_out);
    fwrite(&blobs_limit, sizeof(blobs_limit), 1, f_out);
    fwrite(&height, sizeof(height), 1, f_out);
    fwrite(&size, sizeof(size), 1, f_out);
    fwrite(salt, sizeof(char), 16, f_out);
    save_string(f_out, root_id);
    save_string(f_out, addr);
    HIRB_path_stat.dump_data(f_out);
    vORAM.dump_data(f_out, filename);

    fclose(f_out);
}

void HIRBTree::load_data(const std::string &filename)
{
    FILE *f_in = fopen(filename.c_str(), "rb");

    fread(&SIZE_FACTOR, sizeof(SIZE_FACTOR), 1, f_in);
    fread(&B, sizeof(B), 1, f_in);
    fread(&LeafB, sizeof(LeafB), 1, f_in);
    fread(&keylen, sizeof(keylen), 1, f_in);
    fread(&lenlen, sizeof(lenlen), 1, f_in);
    fread(&hashlen, sizeof(hashlen), 1, f_in);
    fread(&items_limit, sizeof(items_limit), 1, f_in);
    fread(&value_size, sizeof(value_size), 1, f_in);
    fread(&nodesize, sizeof(nodesize), 1, f_in);
    fread(&blobs_limit, sizeof(blobs_limit), 1, f_in);
    fread(&height, sizeof(height), 1, f_in);
    fread(&size, sizeof(size), 1, f_in);
    fread(salt, sizeof(char), 16, f_in);
    load_string(root_id, f_in);
    load_string(addr, f_in);
    HIRB_path_stat.load_data(f_in);

    shared_ptr<grpc::Channel> channel = grpc::CreateCustomChannel(addr,
                                                                  grpc::InsecureChannelCredentials(),
                                                                  get_channel_args());
    vORAM.load_data(channel, f_in, filename);

    fclose(f_in);
}

int HIRBTree::GetStor()
{
    //HIRBpathStat is only used in runtime and does not occupy the client storage
    //Hence we do not count its size
    int ret = 0;

    ret += sizeof(SIZE_FACTOR);
    ret += sizeof(B);
    ret += sizeof(LeafB);
    ret += sizeof(keylen);
    ret += sizeof(lenlen);
    ret += sizeof(hashlen);
    ret += sizeof(items_limit);
    ret += sizeof(value_size);
    ret += sizeof(nodesize);
    ret += sizeof(blobs_limit);
    ret += sizeof(height);
    ret += sizeof(size);
    ret += 16; //salt
    ret += root_id.size();
    ret += addr.size();

    ret += vORAM.GetStor();

    return ret;
}