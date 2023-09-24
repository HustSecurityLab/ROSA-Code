#ifndef VORAM_ROSASERVER_H
#define VORAM_ROSASERVER_H

#include <string>
#include <map>
#include <vector>
#include <array>
#include "../GGM/GGMTree.h"
#include "../BF/BloomFilter.h"

using std::array;

class AuraServer
{
public:
    AuraServer() = default;

    ~AuraServer() = default;

    void Setup();

    void SaveCipher(const array<unsigned char, 32> &label, const array<unsigned char, 32> &tag,
                    const std::vector<array<unsigned char, 32>> &ciphers);

    void Search(std::vector<std::string> &srch_result, const array<unsigned char, 32> &trapdoor,
                const array<unsigned char, 32> &cache_token, const std::vector<GGMNode> &nodes);

    void dump_data(const std::string &filename = "Aura-data");

    void load_data(const std::string &filename = "Aura-data");

    void GetStor(int &EDB_stor, int &Cache_stor);

private:
    std::map<array<unsigned char, 32>, std::pair<array<unsigned char, 32>, vector<array<unsigned char, 32>>>> EDB;
    std::map<array<unsigned char, 32>, std::map<array<unsigned char, 32>, std::string>> Cache;

    void compute_leaf_keys(std::map<long, array<unsigned char, 16>> &keys, const vector<GGMNode> &node_list, int level);
};


#endif