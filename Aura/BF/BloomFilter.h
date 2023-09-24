//
// Created by shangqi on 2020/6/17.
//

#ifndef AURA_BLOOMFILTER_H
#define AURA_BLOOMFILTER_H

#include <bitset>
#include <vector>
#include "../GGM/GGMTree.h"

#include "Hash/SpookyV2.h"

using namespace std;

#define NUM_OF_HASHES 13
#define KEY_LEN 32

class BloomFilter {
public:
    void static add_tag(bitset<GGM_SIZE> &bits, const unsigned char *key) {
        for (int i = 0; i < NUM_OF_HASHES; ++i) {
            long index = SpookyHash::Hash64(key, KEY_LEN, i) % GGM_SIZE;
            bits.set(index);
        }
    }

    bool static might_contain(bitset<GGM_SIZE> &bits, unsigned char *key) {
        bool flag = true;
        for (int i = 0; i < NUM_OF_HASHES; ++i) {
            long index = SpookyHash::Hash64(key, KEY_LEN, i) % GGM_SIZE;
            flag &= bits.test(index);
        }
        return flag;
    }

    vector<long> static get_index(unsigned char *key) {
        vector<long> indexes;
        for (int i = 0; i < NUM_OF_HASHES; ++i) {
            long index = SpookyHash::Hash64(key, KEY_LEN, i) % GGM_SIZE;
            indexes.emplace_back(index);
        }
        return indexes;
    }

    vector<long> static search(bitset<GGM_SIZE> &bits, bool value = true) {
        vector<long> indexes;
        for (int i = 0; i < GGM_SIZE; ++i) {
            if(bits[i] == value) {
                indexes.emplace_back(i);
            }
        }
        return indexes;
    }
};


#endif //AURA_BLOOMFILTER_H
