#ifndef JANUSPP256_CONSTRAINED_PRF_H
#define JANUSPP256_CONSTRAINED_PRF_H

#include <cstdio>
#include <vector>
#include <array>

struct ConstrainedKeyData
{
    std::array<unsigned char, 16> key_data;
    int level;
    unsigned int path;
};

struct ConstrainedKey
{
    ~ConstrainedKey() = default;
    ConstrainedKey() = default;

    size_t size();

    int hash(unsigned char *out);

    unsigned int current_permitted = 0;
    unsigned int max_permitted = 0;
    std::vector<ConstrainedKeyData> permitted_keys;

    int write_to_file(FILE *f_out);

    int read_from_file(FILE *f_in);
};

class ConstrainedPRF
{
public:
    ConstrainedPRF();

    int Eval(unsigned char *K, unsigned int per_num, unsigned char *out);

    int Eval(ConstrainedKey &key, unsigned int counter, unsigned char *out);

    int Constrain(const unsigned char *K, unsigned int per_num, ConstrainedKey &out);

private:
    int _Eval_from_path(unsigned char *key, unsigned int tag, int level, unsigned char *out_result);

    //for numbers from 0 to per_num-1;
    int _Constrain_internal_nodes(const unsigned char *K, unsigned int per_num, ConstrainedKey &out);

    int _Constrain_last_nodes(const unsigned char *K, unsigned int per_num, ConstrainedKey &out);

    unsigned char _data_0[16] = {}, _data_1[16] = {};
};
#endif
