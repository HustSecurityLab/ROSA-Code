#ifndef VORAMCLIENT_H
#define VORAMCLIENT_H

#include <map>
#include <string>
#include <cmath>
#include <stack>
#include <set>
#include <vector>
#include <thread>
#include "vORAMBucket.h"
#include <grpcpp/create_channel.h>
#include "rosa.grpc.pb.h"

class vORAMClient
{
public:
    vORAMClient() = default;
    ~vORAMClient();

    void Setup(int nodesize, int node_num, int idlen, int keylen,
               std::shared_ptr<grpc::Channel> channel, const std::string &srv_addr = "127.0.0.1:54324",
               bool sync = true);

    void insert(std::string &id_out, unsigned char *blk, int blk_len);

    void remove(std::string &blk_out, const std::string &id);

    void update(std::string &id_out, std::string &blob_out, const std::string &id, unsigned char *blk, int blk_len);

    void idgen(std::string &id_out);

    void evict(const std::string &id);

    void writeback(const std::string &id);

    void finalize();

    void dump_data(FILE *f_out, const std::string &name = "HIRB");

    void load_data(std::shared_ptr<grpc::Channel> channel, FILE *f_in, const std::string &name = "HIRB");

    std::map<std::string, std::string> stash;

    void batch_evict(const std::string &id0, const std::string &id1);

    int GetStor();

private:
    std::string addr;
    std::map<int, Bucket> cache;
    std::set<int> fetched_paths;
    std::set<int> written_node;
    std::vector<std::string> id_to_write;
    std::map<int, std::string> pre_fetched_nodes;
    int levels, nodesize, idlen, keylen, lenlen;
    bool sync;
    unsigned char key[32];

    std::unique_ptr<ROSA::ROSASSE::Stub> stub_;

    void recursively_init_voram(std::map<int, std::string> &encryped_store, Bucket &par_node, int cur_id, int cur_level, int max_level);

    void calculate_node_list(std::vector<int> &node_id_list, const std::string &id);

    void find_blob_can_reside_in_cur_node_from_stash(std::set<std::string> &out, int node_id, int offset);

    void srv_setup();

    void srv_put(const std::map<int, std::string> &data);

    void srv_get(std::map<int, std::string> &data, std::vector<int> &node_list);

    void srv_dump(const std::string &name);

    void srv_load(const std::string &name);

    void srv_batch_get(std::set<int> &node_list);

    void srv_batch_put(const std::map<int, std::string> &data);
};

int voram_clog(int x, int b = 2);
int estimate_idlen(int N);
int estimate_nodesize(int blob_size, int nblobs, int idlen, int keylen);

#endif