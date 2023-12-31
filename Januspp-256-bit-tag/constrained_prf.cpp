#include "constrained_prf.h"
#include <cstring>

extern "C"
{
#include <openssl/sha.h>
#include <openssl/aes.h>
}
#include "CommonUtils.h"

size_t ConstrainedKey::size()
{
    size_t ret;

    ret = 2 * sizeof(int);
    ret += (16 + 2 * sizeof(int)) * permitted_keys.size();

    return ret;
}

int ConstrainedKey::hash(unsigned char *out)
{
    unsigned char buf1[64], buf2[32];

    memset(out, 0, 32);

    if (this->current_permitted == 0)
        return 0;

    memset(buf1, 0, 64);
    SHA256(this->permitted_keys[0].key_data.data(), 16, buf1 + 32);

    for (unsigned long i = 1; i < this->permitted_keys.size(); i++)
    {
        SHA256(this->permitted_keys[i].key_data.data(), 16, buf1);
        SHA256(buf1, 64, buf2);
        memcpy(buf1 + 32, buf2, 32);
    }

    memcpy(out, buf1, 32);
    return 1;
}

int ConstrainedKey::write_to_file(FILE *f_out)
{
    size_t number_of_keys = this->permitted_keys.size();

    fwrite(&(this->max_permitted), sizeof(int), 1, f_out);
    fwrite(&(this->current_permitted), sizeof(int), 1, f_out);
    fwrite(&number_of_keys, sizeof(size_t), 1, f_out);
    for (size_t i = 0; i < number_of_keys; i++)
    {
        ConstrainedKeyData &key_data = this->permitted_keys[i];
        fwrite(&(key_data.path), sizeof(unsigned int), 1, f_out);
        fwrite(&(key_data.level), sizeof(int), 1, f_out);
        fwrite(key_data.key_data.data(), sizeof(unsigned char), 16, f_out);
    }

    return 1;
}

int ConstrainedKey::read_from_file(FILE *f_in)
{
    size_t number_of_keys;

    this->permitted_keys.clear();

    fread(&(this->max_permitted), sizeof(int), 1, f_in);
    fread(&(this->current_permitted), sizeof(int), 1, f_in);
    fread(&number_of_keys, sizeof(size_t), 1, f_in);
    for (size_t i = 0; i < number_of_keys; i++)
    {
        ConstrainedKeyData key_data;
        fread(&(key_data.path), sizeof(unsigned int), 1, f_in);
        fread(&(key_data.level), sizeof(int), 1, f_in);
        fread(key_data.key_data.data(), sizeof(unsigned char), 16, f_in);
        this->permitted_keys.emplace_back(key_data);
    }

    return 1;
}

ConstrainedPRF::ConstrainedPRF()
{
    for (int i = 0; i < 16; i++)
    {
        if (i % 2 == 1)
        {
            _data_0[i] = 1;
            _data_1[i] = 0;
        }
        else
        {
            _data_0[i] = 0;
            _data_1[i] = 1;
        }
    }
}

int ConstrainedPRF::Eval(unsigned char *K, unsigned int per_num, unsigned char *out)
{
    return this->_Eval_from_path(K, per_num, 0, out);
}

int ConstrainedPRF::_Eval_from_path(unsigned char *key, unsigned int tag, int level, unsigned char *out_result)
{
    unsigned char tmp1[64], tmp2[64];
    unsigned int mask = 1u << 31u;
    unsigned int mask_inv = ~(1u << 31u);

    for (int i = 0; i < level; i++)
        mask = (mask >> 1u) & mask_inv;

    memcpy(tmp1, key, 16);
    memcpy(tmp2, key, 16);

    for (int i = level; i < 32; i++)
    {
        unsigned char *data_to_enc;

        if ((mask & tag) == 0)
            data_to_enc = _data_0;
        else
            data_to_enc = _data_1;

        if (i % 2 == 0)
            aes_cbc_prf(tmp2, tmp1, data_to_enc);
        else
            aes_cbc_prf(tmp1, tmp2, data_to_enc);

        mask = (mask >> 1u) & mask_inv;
    }

    memcpy(out_result, tmp1, 16);

    return 1;
}

int ConstrainedPRF::Constrain(const unsigned char *K, unsigned int per_num, ConstrainedKey &out)
{
    out.current_permitted = per_num;
    out.max_permitted = ~0u;
    out.permitted_keys.clear();

    if (per_num == out.max_permitted)
    {
        ConstrainedKeyData _data;
        _data.level = 0;
        memcpy(_data.key_data.data(), K, 16);
        out.permitted_keys.emplace_back(_data);
        return 1;
    }
    //path of 1~per_num-1
    this->_Constrain_internal_nodes(K, per_num, out);
    //path of per_num
    this->_Constrain_last_nodes(K, per_num, out);

    return 1;
}

int ConstrainedPRF::_Constrain_internal_nodes(const unsigned char *K, unsigned int per_num, ConstrainedKey &out)
{
    unsigned int mask = 1u << 31u;
    unsigned int path_mask_all_bits = 1u << 31u;
    unsigned char buf1[64], buf2[64];
    //all nodes excluding per_num
    for (unsigned char i = 1; i <= 32; i++)
    {
        if ((mask & per_num) != 0)
        {
            unsigned int path_mask = 1u << 31u;
            unsigned char *data_to_enc;
            memcpy(buf1, K, 16);

            for (unsigned int j = 0; j < i - 1; j++)
            {
                if ((path_mask & per_num) == 0)
                    data_to_enc = _data_0;
                else
                    data_to_enc = _data_1;

                if (j % 2 == 0)
                    aes_cbc_prf(buf2, buf1, data_to_enc);

                else
                    aes_cbc_prf(buf1, buf2, data_to_enc);

                path_mask = (path_mask >> 1u) & (~(1u << 31u));
            }

            ConstrainedKeyData _key;
            _key.level = i;
            _key.path = path_mask_all_bits & per_num;
            _key.path = _key.path ^ mask;
            data_to_enc = _data_0;

            if (i % 2 == 0)
            {
                aes_cbc_prf(buf1, buf2, data_to_enc);
                memcpy(_key.key_data.data(), buf1, 16);
            }
            else
            {
                aes_cbc_prf(buf2, buf1, data_to_enc);
                memcpy(_key.key_data.data(), buf2, 16);
            }
            out.permitted_keys.emplace_back(_key);
        }
        mask >>= 1u;
        path_mask_all_bits = (path_mask_all_bits >> 1u) | (1u << 31u);
    }

    return 1;
}

int ConstrainedPRF::_Constrain_last_nodes(const unsigned char *K, unsigned int per_num, ConstrainedKey &out)
{
    unsigned char buf1[64], buf2[64];
    unsigned int path_mask = 1u << 31u;
    unsigned char *data_to_enc;

    memcpy(buf1, K, 16);
    for (int i = 0; i < 32; i++)
    {
        if ((path_mask & per_num) == 0)
            data_to_enc = _data_0;
        else
            data_to_enc = _data_1;

        if (i % 2 == 0)
            aes_cbc_prf(buf2, buf1, data_to_enc);
        else
            aes_cbc_prf(buf1, buf2, data_to_enc);

        path_mask = (path_mask >> 1u) & (~(1u << 31u));
    }
    ConstrainedKeyData _data;
    _data.level = 32;
    _data.path = per_num;
    memcpy(_data.key_data.data(), buf1, 16);
    out.permitted_keys.emplace_back(_data);
    return 1;
}

int ConstrainedPRF::Eval(ConstrainedKey &key, unsigned int counter, unsigned char *out)
{
    unsigned int prefix = 1u << 31u;

    memset(out, 0, 16);

    if (counter > key.current_permitted)
        return 0;

    for (auto &k: key.permitted_keys)
    {
        prefix = 1u << 31u;
        for (int j = 1; j < k.level; j++)
            prefix = (prefix >> 1u) | (1u << 31u);
        if ((prefix & k.path) == (prefix & counter))
            return _Eval_from_path(k.key_data.data(), counter, k.level, out);
    }

    return 1;
}
