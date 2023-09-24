//
// Created by shangqi on 2020/6/20.
//

#ifndef AURA_GGMTREE_H
#define AURA_GGMTREE_H

#include <bitset>
#include <cmath>
#include <cstring>
#include <vector>

#include "GGMNode.h"
#include "../CommonUtils.h"

using namespace std;

class GGMTree
{

public:
    void static derive_key_from_tree(uint8_t *current_key, long offset,
                                     int target_level,int start_level=ceil(log2(GGM_SIZE)));

    vector<GGMNode> static min_coverage(vector<GGMNode> node_list);

    int static get_level();
};


#endif //AURA_GGMTREE_H