#ifndef HIRBPATHSTAT_H
#define HIRBPATHSTAT_H

#include <string>
#include "HIRBTreeNode.h"

class HIRBpathStat
{
public:
    HIRBpathStat()=default;
    ~HIRBpathStat()=default;
    void setup(int height);

    void dump_data(FILE *f_out);
    void load_data(FILE *f_in);

    std::string id0, id0p, id1, id1p;
    std::string cid0, cid1, cid0p, cid1p;
    std::string label_hash;
    HIRBTreeNode v0, v1;
    bool found;
    int l, H;
};

#endif