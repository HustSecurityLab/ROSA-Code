#ifndef AURACLIENT_H
#define AURACLIENT_H

#include <string>
#include <map>
#include <vector>
#include <bitset>
#include <array>
#include "../GGM/GGMNode.h"
#include "../CommonUtils.h"

using std::array;

class AuraClient
{
public:
    AuraClient();

    ~AuraClient() = default;

    void Setup();

    void Update(array<unsigned char, 32> &label, array<unsigned char, 32> &tag,
                std::vector<array<unsigned char, 32>> &cipher, const std::string &keyword,
                const std::string &id, OP op);

    void Trapdoor(array<unsigned char, 32> &trapdoor, array<unsigned char, 32> &cache_token,
                  std::vector<GGMNode> &nodes, const std::string &keyword);

    void dump_data(const std::string &filename = "Aura-data");

    void load_data(const std::string &filename = "Aura-data");

    int GetStor();

private:
    std::map<std::string, int> counter;
    std::map<std::string, std::pair<array<unsigned char, 16>, std::bitset<GGM_SIZE>>> msk;
    unsigned char Kt[16];

    int bitset_to_bytes(unsigned char *out, const std::bitset<GGM_SIZE> &in);

    int biteset_from_bytes(std::bitset<GGM_SIZE> &out, const unsigned char *in);

};

#endif
