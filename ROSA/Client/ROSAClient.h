#ifndef VORAM_ROSACLIENT_H
#define VORAM_ROSACLIENT_H

#include <string>
#include <map>
#include <vector>
#include <bitset>
#include <array>
#include "HIRBTree.h"
#include "../GGM/GGMNode.h"
#include "../CommonUtils.h"

class ROSAClient
{
public:
    ROSAClient() = delete;

    ROSAClient(int omap_cap = 1000000, const std::string &srv_addr = "127.0.0.1:54324");

    ~ROSAClient() = default;

    void Setup();

    void Update(std::array<unsigned char, 32> &label, std::vector<std::array<unsigned char, 32>> &cipher,
                const std::string &keyword, const std::string &id, RosaOp op);

    void Trapdoor(std::array<unsigned char, 32> &K_s, int &cnt_srch, int &cnt_upd,
                  std::array<unsigned char, 32> &L_cache, std::vector<GGMNode> &nodes, const std::string &keyword);

    void dump_data(const std::string &filename = "ROSA-data");

    void load_data(const std::string &filename = "ROSA-data");

    int GetStor();

private:
    HIRBTree hirbTree;
    int omap_cap;
    std::string srv_addr;
    std::map<std::string, std::pair<int, int>> counter; //the first is cnt^{srch}, second is cnt^{upd}
    std::map<std::string, std::pair<std::array<unsigned char, 16>, std::bitset<GGM_SIZE>>> msk;
    unsigned char key[16];

    int bitset_to_bytes(unsigned char *out, const std::bitset<GGM_SIZE> &in);

    int biteset_from_bytes(std::bitset<GGM_SIZE> &out, const unsigned char *in);

};

#endif
