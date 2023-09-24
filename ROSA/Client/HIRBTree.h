#ifndef HIRBTREE_H
#define HIRBTREE_H

#include <string>
#include <vector>
#include <map>
#include "vORAMClient.h"
#include "HIRBTreeNode.h"
#include "HIRBpathStat.h"

class HIRBTree
{
public:
    HIRBTree() = delete;
    // items_limit: the maximum number of items stored in HIRB
    HIRBTree(int items_limit, const std::string &addr = "127.0.0.1:54324",
             int value_size = 12, int bucket_size = 4096, int size_factor = 6);
    ~HIRBTree() = default;

    void insert(const std::string &label, const std::string &value);

    void get(std::string &val_out, const std::string &label);

    void dump_data(const std::string &filename = "HIRB-tree-data");

    void load_data(const std::string &filename = "HIRB-tree-data");
    int GetStor();

private:
    vORAMClient vORAM;
    int SIZE_FACTOR;
    int B, LeafB, keylen, lenlen, hashlen, items_limit;
    int value_size, nodesize, blobs_limit, height, size;
    unsigned char salt[16];
    std::string root_id, addr;
    HIRBpathStat HIRB_path_stat;
    void estimate_B(int &B_out, int &LeafB_out,
                    int nodesize, int idlen, int keylen,
                    int lenlen, int hashlen, int valsize);
    int get_height(const unsigned char *label_hash,
                   int hash_len = 20);
    void hirbinit();

    void HIRBpath_init(const std::string &label_hash);
    bool HIRBpath_proceed();
    void HIRBpath_finalize();
};

#endif