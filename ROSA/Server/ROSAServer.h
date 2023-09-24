#ifndef VORAM_ROSASERVER_H
#define VORAM_ROSASERVER_H

#include <string>
#include <map>
#include <vector>
#include <array>
#include "../GGM/GGMTree.h"
#include "../BF/BloomFilter.h"

class ROSAServer
{
public:
    ROSAServer() = default;

    ~ROSAServer() = default;

    void Setup();

    void SaveCipher(const std::array<unsigned char, 32> &label,
                    const std::vector<std::array<unsigned char, 32>> &ciphers);

    void Search(std::vector<std::string> &srch_result, const std::array<unsigned char, 32> &K_s,
                int cnt_srch, int cnt_upd, const std::array<unsigned char, 32> &L_cache,
                const std::vector<GGMNode> &nodes);

    void dump_data(const std::string &filename="ROSA-data");

    void load_data(const std::string &filename="ROSA-data");

    void GetStor(int &CDB_stor, int &Cache_stor);

private:
    std::map<std::array<unsigned char, 32>, vector<std::array<unsigned char, 32>>> CDB;
    std::map<std::array<unsigned char, 32>, std::map<std::string, std::string>> Cache;

    void compute_leaf_keys(std::map<long, std::array<unsigned char, 16>> &keys,
                           const vector<GGMNode> &node_list, int level);
};


#endif