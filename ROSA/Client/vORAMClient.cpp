#include "vORAMClient.h"
#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <mutex>
#include <thread>
#include <chrono>
#include "../CommonUtils.h"
#include <grpc++/grpc++.h>
#include "rosa.grpc.pb.h"

extern "C"
{
#include <openssl/sha.h>
#include <openssl/rand.h>
#include "unistd.h"
}

using grpc::Channel;
using grpc::ClientAsyncResponseReader;
using grpc::ClientContext;
using grpc::CompletionQueue;
using grpc::Status;
using namespace std;

extern double bench_clnt_time;

int voram_clog(int x, int b)
{
    if (x < b)
        return 1;
    else
        return ceil(log(x) / log(b));
}

int estimate_idlen(int N)
{
    return ceil((40 + voram_clog(N * (N - 1))) / 8);
}

int estimate_nodesize(int blob_size, int nblobs, int idlen, int keylen)
{
    int nolen = 2 * keylen + nblobs * (idlen + blob_size);
    return nolen + nblobs * voram_clog(2 * nolen - 2 * keylen - 2, 8);
}

vORAMClient::~vORAMClient()
{
}

void vORAMClient::recursively_init_voram(std::map<int, std::string> &encryped_store,
                                         Bucket &par_node, int cur_id, int cur_level, int max_level)
{
    Bucket child[2];
    string tmp_str;
    int child_id;

    if (cur_level > max_level)
        return;

    for (int i = 0; i <= 1; i++)
    {
        child[i].Setup(this->nodesize, this->keylen, this->lenlen, this->idlen);
        RAND_bytes(child[i].key1(), this->keylen);
        RAND_bytes(child[i].key2(), this->keylen);
    }

    child[0].to_encrypted_string(tmp_str, par_node.key1(), this->keylen);
    child_id = (cur_id << 1);
    encryped_store[child_id] = tmp_str;
    recursively_init_voram(encryped_store, child[0], child_id, cur_level + 1, max_level);

    child[1].to_encrypted_string(tmp_str, par_node.key2(), this->keylen);
    child_id = (cur_id << 1) + 1;
    encryped_store[child_id] = tmp_str;
    recursively_init_voram(encryped_store, child[1], child_id, cur_level + 1, max_level);
}

void vORAMClient::Setup(int nodesize, int node_num, int idlen, int keylen, shared_ptr<grpc::Channel> channel,
                        const std::string &srv_addr, bool sync)
{
    int node_id = 0; // we assume that the maximum levels of vORAM node will not exceed 31
    Bucket bucket;
    string tmp_str;
    map<int, string> encryped_store;

    this->sync = sync;
    this->addr = srv_addr;
    this->id_to_write.clear();
    this->stash.clear();
    this->cache.clear();
    this->nodesize = nodesize;
    this->levels = voram_clog(node_num) - 1;
    if (idlen <= 0)
        this->idlen = estimate_idlen(node_num);
    else
        this->idlen = idlen;
    if (keylen <= 0)
        this->keylen = 16;
    else
        this->keylen = keylen;
    RAND_bytes(this->key, this->keylen);
    this->lenlen = (log2((this->nodesize - 2 * this->keylen - 2)) + 7) / 8;

    bucket.Setup(this->nodesize, this->keylen, this->lenlen, this->idlen);
    node_id = 1;
    RAND_bytes(bucket.key1(), this->keylen);
    RAND_bytes(bucket.key2(), this->keylen);
    bucket.to_encrypted_string(tmp_str, this->key, this->keylen);
    encryped_store[node_id] = tmp_str;

    recursively_init_voram(encryped_store, bucket, 1, 1, this->levels);

    if (stub_)
        delete stub_.release();
    stub_ = ROSA::ROSASSE::NewStub(channel);

    srv_setup();
    srv_put(encryped_store);
}

void vORAMClient::idgen(string &id_out)
{
    unsigned char buf[128];
    int mask = 1 << (levels - 1);

    memset(buf, 0, 128);

    while ((buf[0] == 0) || ((mask & (*((int *)(buf + idlen - sizeof(int))))) == 0))
        RAND_bytes(buf, idlen);

    id_out.assign((char *)buf, idlen);
}

void vORAMClient::calculate_node_list(vector<int> &node_id_list, const string &id)
{
    int mask = (1 << levels) - 1;
    int leaf_node_id = mask & *((int *)(id.c_str() + idlen - sizeof(int)));

    for (int i = 0; i < levels; i++)
    {
        node_id_list.emplace_back(leaf_node_id);
        leaf_node_id >>= 1;
    }
}

void vORAMClient::batch_evict(const std::string &id0, const std::string &id1)
{
    chrono::steady_clock::time_point begin, end;
    chrono::duration<double, std::micro> elapsed;
    if (id0.empty() || id1.empty())
        return;
    vector<int> node_id_list0, node_id_list1;
    vector<vector<int>> node_id_lists;
    set<int> nodes_to_fetch;
    unsigned char *key;
    map<int, string> fetched_nodes;
    std::string str_tmp;

    // begin = chrono::steady_clock::now();

    pre_fetched_nodes.clear();

    if (id0[0] != 0)
    {
        calculate_node_list(node_id_list0, id0);
        fetched_paths.emplace(node_id_list0[0]);
        for (int i : node_id_list0)
            nodes_to_fetch.emplace(i);
    }

    if (id1[0] != 0)
    {
        calculate_node_list(node_id_list1, id1);
        fetched_paths.emplace(node_id_list1[0]);
        for (int i : node_id_list1)
            nodes_to_fetch.emplace(i);
    }

    // end = chrono::steady_clock::now();
    // elapsed = end - begin;
    // bench_clnt_time += elapsed.count();

    srv_batch_get(nodes_to_fetch);

    // begin = chrono::steady_clock::now();
    key = this->key;

    node_id_lists.emplace_back(node_id_list0);
    node_id_lists.emplace_back(node_id_list1);
    for (auto &node_id_list : node_id_lists)
    {
        for (int fnode : node_id_list)
            fetched_nodes[fnode] = pre_fetched_nodes[fnode];
        for (auto itr = node_id_list.rbegin(); itr != node_id_list.rend(); itr++)
        {
            Bucket bucket;

            if (cache.find(*itr) == cache.end())
            {
                str_tmp = fetched_nodes[*itr];
                bucket.from_encrypted_string(str_tmp, key, keylen);
                cache[*itr] = bucket;
            }

            if ((itr + 1) != node_id_list.rend())
            {
                if (*(itr + 1) % 2)
                {
                    key = cache[*itr].key2();
                }
                else
                {
                    key = cache[*itr].key1();
                }
            }
        }
        for (auto itr = node_id_list.rbegin(); itr != node_id_list.rend(); itr++)
        {
            Bucket &bucket = cache[*itr];
            int node_blob_idx = 0;
            while (bucket.id(node_blob_idx))
            {
                string blob_id, blob;

                blob_id.assign((char *)bucket.id(node_blob_idx), idlen);
                blob.assign((char *)bucket.blob(node_blob_idx), bucket.len(node_blob_idx));

                if (stash.find(blob_id) != stash.end())
                    stash[blob_id] = stash[blob_id] + blob;
                else
                    stash[blob_id] = blob;
                node_blob_idx++;
            }
            bucket.remaining = bucket.nodesize - 2 * bucket.keylen;
            memset(bucket.data_ + 2 * bucket.keylen, 0, bucket.remaining);
        }
    }
    // end = chrono::steady_clock::now();
    // elapsed = end - begin;
    // bench_clnt_time += elapsed.count();
}

void vORAMClient::srv_batch_get(std::set<int> &node_list)
{
    grpc::ClientContext ctx;
    ROSA::ORAMBlockNo req;
    ROSA::ORAMBlock block;

    for (int nodeno : node_list)
    {
        if (cache.find(nodeno) == cache.end())
        {
            req.add_no(nodeno);
        }
    }
    std::unique_ptr<grpc::ClientReader<ROSA::ORAMBlock>> reader(stub_->ORAMGet(&ctx, req));

    while (reader->Read(&block))
        pre_fetched_nodes[block.no()] = block.data();
}

void vORAMClient::evict(const string &id)
{
    if (id.empty())
        return;
    if (id[0] == 0)
        return;

    vector<int> node_id_list;
    string str_tmp;
    unsigned char *key;
    map<int, string> fetched_nodes;

    calculate_node_list(node_id_list, id);

    // record which path has been fetched
    fetched_paths.emplace(node_id_list[0]);

    srv_get(fetched_nodes, node_id_list);
    key = this->key;
    for (auto itr = node_id_list.rbegin(); itr != node_id_list.rend(); itr++)
    {
        Bucket bucket;

        if (cache.find(*itr) == cache.end())
        {
            str_tmp = fetched_nodes[*itr];
            bucket.from_encrypted_string(str_tmp, key, keylen);
            cache[*itr] = bucket;
        }

        if ((itr + 1) != node_id_list.rend())
        {
            if (*(itr + 1) % 2)
            {
                key = cache[*itr].key2();
            }
            else
            {
                key = cache[*itr].key1();
            }
        }
    }
    for (auto itr = node_id_list.rbegin(); itr != node_id_list.rend(); itr++)
    {
        Bucket &bucket = cache[*itr];
        int node_blob_idx = 0;
        while (bucket.id(node_blob_idx))
        {
            string blob_id, blob;

            blob_id.assign((char *)bucket.id(node_blob_idx), idlen);
            blob.assign((char *)bucket.blob(node_blob_idx), bucket.len(node_blob_idx));

            if (stash.find(blob_id) != stash.end())
                stash[blob_id] = stash[blob_id] + blob;
            else
                stash[blob_id] = blob;
            node_blob_idx++;
        }
        bucket.remaining = bucket.nodesize - 2 * bucket.keylen;
        memset(bucket.data_ + 2 * bucket.keylen, 0, bucket.remaining);
    }
}

void vORAMClient::find_blob_can_reside_in_cur_node_from_stash(set<string> &out, int node_id, int offset)
{
    int total_size = 0;
    for (const auto &itr : stash)
    {
        int mask = (1 << levels) - 1;
        int leaf_node_id = mask & *((int *)(itr.first.c_str() + idlen - sizeof(int)));

        if ((leaf_node_id >> offset) == node_id)
        {
            out.emplace(itr.first);
            total_size += itr.second.length();
            if (total_size >= nodesize)
                break;
        }
    }
}

void vORAMClient::writeback(const string &id)
{
    if (!this->sync)
    {
        this->id_to_write.emplace_back(id);
        return;
    }

    vector<int> node_id_list;
    int offset = 0;

    calculate_node_list(node_id_list, id);

    if (fetched_paths.find(node_id_list[0]) == fetched_paths.end())
        return;
    for (auto itr = node_id_list.begin(); itr != node_id_list.end(); itr++)
    {
        set<string> blobs_reside_in_cur_node;
        Bucket &bucket = cache[*itr];

        // cout << *itr << " ";

        find_blob_can_reside_in_cur_node_from_stash(blobs_reside_in_cur_node, *itr, offset);
        offset += 1;

        while ((!blobs_reside_in_cur_node.empty()) && (bucket.remaining > idlen + lenlen))
        {
            string blob_id = *blobs_reside_in_cur_node.begin();
            blobs_reside_in_cur_node.erase(blobs_reside_in_cur_node.begin());

            if (stash[blob_id].length() <= bucket.remaining - idlen - lenlen)
            {
                bucket.append_blob((unsigned char *)blob_id.c_str(),
                                   (unsigned char *)stash[blob_id].c_str(),
                                   (int)stash[blob_id].length());
                stash.erase(blob_id);
            }
            else
            {
                int mask = (1 << levels) - 1;
                int leaf_node_id = mask & *((int *)(blob_id.c_str() + idlen - sizeof(int)));
                if (leaf_node_id != node_id_list[0])
                    continue;
                int written_len = bucket.remaining - idlen - lenlen;
                int blob_len = stash[blob_id].length();

                bucket.append_blob((unsigned char *)blob_id.c_str(),
                                   (unsigned char *)stash[blob_id].c_str() + blob_len - written_len,
                                   written_len);

                stash[blob_id] = stash[blob_id].substr(0, blob_len - written_len);
            }
        }
    }
    // cout << endl;
}

void vORAMClient::finalize()
{
    chrono::steady_clock::time_point begin, end;
    chrono::duration<double, std::micro> elapsed;

    map<int, string> written_nodes;

    // begin = chrono::steady_clock::now();

    if (!this->sync)
    {
        this->sync = true;
        for (auto &id : id_to_write)
            writeback(id);
        this->sync = false;
        id_to_write.clear();
    }

    RAND_bytes(this->key, keylen);

    for (int node_id : fetched_paths)
    {
        for (int i = 0; i < levels; i++)
        {
            unsigned char *enc_key;
            string enc_node;

            if (written_node.find(node_id) != written_node.end())
                break;
            written_node.emplace(node_id);

            if (node_id == 1)
                enc_key = this->key;
            else
            {
                int par_node_id = node_id >> 1;
                Bucket &bucket = cache[par_node_id];
                if (node_id % 2)
                {
                    if (written_node.find(par_node_id) == written_node.end())
                        RAND_bytes(bucket.key2(), keylen);
                    enc_key = bucket.key2();
                }
                else
                {
                    if (written_node.find(par_node_id) == written_node.end())
                        RAND_bytes(bucket.key1(), keylen);
                    enc_key = bucket.key1();
                }
            }

            cache[node_id].to_encrypted_string(enc_node, enc_key, keylen);
            /*only for debug to use local storage*/
            written_nodes[node_id] = enc_node;

            node_id >>= 1;
        }
    }
    written_node.clear();
    cache.clear();
    fetched_paths.clear();

    // end = chrono::steady_clock::now();
    // elapsed = end - begin;
    // bench_clnt_time += elapsed.count();

    srv_batch_put(written_nodes);
    // srv_put(written_nodes);
}

void vORAMClient::insert(string &id_out, unsigned char *blk, int blk_len)
{
    string id0, blob;

    idgen(id0);
    evict(id0);

    idgen(id_out);
    blob.assign((const char *)blk, blk_len);
    stash[id_out] = blob;
    writeback(id0);
}

void vORAMClient::remove(string &blk_out, const string &id)
{
    evict(id);
    blk_out = stash[id];
    stash.erase(id);
    writeback(id);
}

void vORAMClient::update(string &id_out, string &blob_out, const string &id, unsigned char *blk, int blk_len)
{
    string blob;

    evict(id);
    if (stash.find(id) != stash.end())
        blob_out = stash[id];
    else
        blob_out = "";
    stash.erase(id);

    idgen(id_out);
    if (blk)
        blob.assign((const char *)blk, blk_len);
    else
        blob = blob_out;
    stash[id_out] = blob;
    writeback(id);
}

void vORAMClient::srv_setup()
{
    grpc::ClientContext ctx;
    ROSA::SetupParam req;
    ROSA::Stat reply;

    Status stat = stub_->SetupORAM(&ctx, req, &reply);
}

void vORAMClient::srv_batch_put(const std::map<int, std::string> &data)
{
    grpc::ClientContext ctx;
    ROSA::Stat stat;
    grpc::WriteOptions wopt;
    bool sent = false;

    wopt.clear_corked();

    std::unique_ptr<grpc::ClientWriter<ROSA::ORAMBlock>> writer(stub_->ORAMPut(&ctx, &stat));

    for (auto &itr : data)
    {
        ROSA::ORAMBlock block;

        block.set_no(itr.first);
        block.set_data(itr.second);
        writer->Write(block, wopt);
        if (!sent)
        {
            wopt.set_corked();
            sent = true;
        }
    }
    writer->WritesDone();
    writer->Finish();
}

void vORAMClient::srv_put(const std::map<int, std::string> &data)
{
    grpc::ClientContext ctx;
    ROSA::Stat stat;
    grpc::WriteOptions wopt;
    bool sent = false;

    wopt.clear_corked();

    std::unique_ptr<grpc::ClientWriter<ROSA::ORAMBlock>> writer(stub_->ORAMPut(&ctx, &stat));

    for (auto &itr : data)
    {
        ROSA::ORAMBlock block;

        block.set_no(itr.first);
        block.set_data(itr.second);
        writer->Write(block, wopt);
        if (!sent)
        {
            wopt.set_corked();
            sent = true;
        }
    }
    writer->WritesDone();
    writer->Finish();
}

void vORAMClient::srv_get(std::map<int, std::string> &data, std::vector<int> &node_list)
{
    grpc::ClientContext ctx;
    ROSA::ORAMBlockNo req;
    ROSA::ORAMBlock block;

    for (int nodeno : node_list)
    {
        if (cache.find(nodeno) == cache.end())
        {
            req.add_no(nodeno);
        }
    }
    std::unique_ptr<grpc::ClientReader<ROSA::ORAMBlock>> reader(stub_->ORAMGet(&ctx, req));

    while (reader->Read(&block))
        data[block.no()] = block.data();
}

void vORAMClient::dump_data(FILE *f_out, const std::string &name)
{
    size_t size;
    int tmp_int;

    save_string(f_out, addr);
    fwrite(key, sizeof(char), 32, f_out);
    fwrite(&levels, sizeof(levels), 1, f_out);
    fwrite(&nodesize, sizeof(nodesize), 1, f_out);
    fwrite(&idlen, sizeof(idlen), 1, f_out);
    fwrite(&keylen, sizeof(keylen), 1, f_out);
    fwrite(&lenlen, sizeof(lenlen), 1, f_out);
    if (sync)
        tmp_int = 1;
    else
        tmp_int = 0;
    fwrite(&tmp_int, sizeof(tmp_int), 1, f_out);

    size = stash.size();
    fwrite(&size, sizeof(size), 1, f_out);
    for (auto &itr : stash)
    {
        save_string(f_out, itr.first);
        save_string(f_out, itr.second);
    }

    size = cache.size();
    fwrite(&size, sizeof(size), 1, f_out);
    for (auto &itr : cache)
    {
        string str;
        fwrite(&(itr.first), sizeof(itr.first), 1, f_out);
        itr.second.to_encrypted_string(str, key, keylen);
        save_string(f_out, str);
    }

    size = fetched_paths.size();
    fwrite(&size, sizeof(size), 1, f_out);
    for (auto &itr : fetched_paths)
    {
        fwrite(&itr, sizeof(itr), 1, f_out);
    }

    size = written_node.size();
    fwrite(&size, sizeof(size), 1, f_out);
    for (auto &itr : written_node)
    {
        fwrite(&itr, sizeof(itr), 1, f_out);
    }

    size = id_to_write.size();
    fwrite(&size, sizeof(size), 1, f_out);
    for (auto &itr : id_to_write)
        save_string(f_out, itr);

    srv_dump(name);
}

void vORAMClient::load_data(std::shared_ptr<grpc::Channel> channel, FILE *f_in, const std::string &name)
{

    if (stub_)
        delete stub_.release();
    stub_ = ROSA::ROSASSE::NewStub(channel);

    size_t size;
    int tmp_int;

    load_string(addr, f_in);
    fread(key, sizeof(char), 32, f_in);
    fread(&levels, sizeof(levels), 1, f_in);
    fread(&nodesize, sizeof(nodesize), 1, f_in);
    fread(&idlen, sizeof(idlen), 1, f_in);
    fread(&keylen, sizeof(keylen), 1, f_in);
    fread(&lenlen, sizeof(lenlen), 1, f_in);
    fread(&tmp_int, sizeof(tmp_int), 1, f_in);
    if (tmp_int)
        sync = true;
    else
        sync = false;

    stash.clear();
    cache.clear();
    fetched_paths.clear();
    written_node.clear();

    fread(&size, sizeof(size), 1, f_in);
    for (int i = 0; i < size; i++)
    {
        string str1, str2;
        load_string(str1, f_in);
        load_string(str2, f_in);
        stash[str1] = str2;
    }

    fread(&size, sizeof(size), 1, f_in);
    for (int i = 0; i < size; i++)
    {
        Bucket b;
        int int1;
        string str1;
        fread(&int1, sizeof(int1), 1, f_in);
        load_string(str1, f_in);
        b.from_encrypted_string(str1, key, keylen);
        cache[int1] = b;
    }

    fread(&size, sizeof(size), 1, f_in);
    for (int i = 0; i < size; i++)
    {
        int int1;
        fread(&int1, sizeof(int1), 1, f_in);
        fetched_paths.emplace(int1);
    }

    fread(&size, sizeof(size), 1, f_in);
    for (int i = 0; i < size; i++)
    {
        int int1;
        fread(&int1, sizeof(int1), 1, f_in);
        written_node.emplace(int1);
    }

    fread(&size, sizeof(size), 1, f_in);
    for (int i = 0; i < size; i++)
    {
        string str1;
        load_string(str1, f_in);
        id_to_write.emplace_back(str1);
    }
    srv_load(name);
}

void vORAMClient::srv_dump(const std::string &name)
{
    grpc::ClientContext ctx;
    ROSA::BackParam req;
    ROSA::Stat reply;

    req.set_name(name);
    Status stat = stub_->ORAMBackup(&ctx, req, &reply);
}

void vORAMClient::srv_load(const std::string &name)
{
    grpc::ClientContext ctx;
    ROSA::BackParam req;
    ROSA::Stat reply;

    req.set_name(name);
    Status stat = stub_->ORAMLoad(&ctx, req, &reply);
}

int vORAMClient::GetStor()
{
    // cache, fetched_paths, written_node, id_to_write, pre_fetched_nodes are
    // runtime data. They do not occupy client storage
    int ret = 0;

    ret += addr.size();
    ret += 32;
    ret += sizeof(sync);
    ret += sizeof(this->levels);
    ret += sizeof(this->nodesize);
    ret += sizeof(this->idlen);
    ret += sizeof(this->keylen);
    ret += sizeof(this->lenlen);
    for (const auto &itr : stash)
    {
        ret += itr.first.size();
        ret += itr.second.size();
    }

    return ret;
}