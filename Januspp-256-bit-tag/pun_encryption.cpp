#include <random>
#include <ctime>
#include <cstdlib>
#include <cstring>

extern "C"
{
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
}
#include "pun_encryption.h"
#include "CommonUtils.h"

using std::default_random_engine;

PunEncryptionKey::PunEncryptionKey(int d)
{
    unsigned char buf1[16];
    FILE *f_random = fopen("/dev/urandom", "rb");

    this->max_deletion = d;
    this->current_deleted = 0;

    fread(buf1, sizeof(char), 16, f_random);
    fclose(f_random);

    PuncturedKey key(buf1);
    this->key_data.emplace_back(key);
    memcpy(this->initial_key, buf1, 16);
}

PunEncryptionKey::PunEncryptionKey(const PunEncryptionKey &k)
{
    if (&k == this)
        return;

    this->max_deletion = k.max_deletion;
    this->current_deleted = k.current_deleted;
    this->key_data.clear();

    for (auto &kd:k.key_data)
        this->key_data.emplace_back(kd);

    memcpy(this->initial_key, k.initial_key, 16);
}

PunEncryptionKey &PunEncryptionKey::operator=(const PunEncryptionKey &k)
{
    if (&k == this)
        return *this;

    this->max_deletion = k.max_deletion;
    this->current_deleted = k.current_deleted;
    this->key_data.clear();

    for (auto &kd:k.key_data)
        this->key_data.emplace_back(kd);

    return *this;
}

PunEncryptionKey::~PunEncryptionKey()
{
}

size_t PunEncryptionKey::size()
{
    size_t ret = 0;

    ret = 2 * sizeof(int);

    for (auto &a:this->key_data)
        ret += a.size();

    return ret;
}

int PunEncryptionKey::hash(unsigned char *hash_out)
{
    unsigned char buf1[64], buf2[32];
    if (this->key_data.empty())
        return 0;
    this->key_data[0].hash(buf1);
    for (int i = 1; i < this->key_data.size(); i++)
    {
        this->key_data[i].hash(buf1 + 32);
        SHA256(buf1, 64, buf2);
        memcpy(buf1, buf2, 32);
    }
    memcpy(hash_out, buf1, 32);
    return 1;
}

PunEncryptionKey::PunEncryptionKey(int d, unsigned char *data)
{
    memcpy(this->initial_key, data, 16);
    this->max_deletion = d;
    this->current_deleted = 0;
}

PunEncryptionKey *PunEncryption::generate_key(int max_deletion)
{
    auto ret = new PunEncryptionKey(max_deletion);
    return ret;
}

int PunEncryption::puncture(PunEncryptionKey *key, PunTag &tag, PuncturedKey *psk)
{
    if (key->current_deleted >= key->max_deletion)
        return 0;

    unsigned char buf1[32];
    auto &key_to_punc = key->key_data[key->current_deleted];
    //next key
    if (key->current_deleted < key->max_deletion + 1)
    {
        SHA256(key_to_punc.keydata[0].data(), 16, buf1);
        PuncturedKey new_key(buf1);
        key->key_data.emplace_back(new_key);
    }
    PuncturedKey key_punced;
    this->_punc_prf.Punc(key_to_punc.keydata[0].data(), tag, key_punced);

    key->key_data[key->current_deleted] = key_punced;
    if (psk != nullptr)
        *psk = key_punced;
    key->current_deleted++;
    return 1;
}

int PunEncryption::encrypt(PunEncryptionKey *key, PunTag &tag, const char *id, unsigned char *IV, unsigned char *output)
{
    unsigned char buf1[32], buf2[32], buf3[32], buf4[32], iv[16];
    AES_KEY aes_key;

    memset(buf2, 0, 16);
    RAND_bytes(iv, 16);
    memcpy(IV, iv, 16);

    for (auto &kd:key->key_data)
    {
        if (this->_punc_prf.Eval(kd, tag, buf1) == 0)
            return 0;
        for (int i = 0; i < 16; i++)
        {
            buf2[i] = buf2[i] ^ buf1[i];
        }
    }
    if (key->current_deleted < key->max_deletion)
        memcpy(buf3, key->key_data[key->current_deleted].keydata[0].data(), 16);
    for (int i = key->key_data.size(); i < key->max_deletion; i++)
    {
        SHA256(buf3, 16, buf4);
        this->_punc_prf.Eval(buf4, tag, buf1);
        for (int j = 0; j < 16; j++)
        {
            buf2[j] = buf2[j] ^ buf1[j];
        }
        memcpy(buf3, buf4, 16);
    }

    encrypt_id(output, id, buf2);

    return 1;
}

int PunEncryption::decrypt(std::string &id, PunEncryptionKey *key, DianaData &in)
{
    unsigned char buf1[32], buf2[32], buf3[32], buf4[32];

    memset(buf2, 0, 16);

    for (auto &kd:key->key_data)
    {
        if (this->_punc_prf.Eval(kd, in.tag, buf1) == 0)
            return 0;
        for (int i = 0; i < 16; i++)
        {
            buf2[i] = buf2[i] ^ buf1[i];
        }
    }
    if (key->current_deleted < key->max_deletion)
        memcpy(buf3, key->key_data[key->current_deleted].keydata[0].data(), 16);
    for (int i = key->key_data.size(); i < key->max_deletion; i++)
    {
        SHA256(buf3, 16, buf4);
        this->_punc_prf.Eval(buf4, in.tag, buf1);
        for (int j = 0; j < 16; j++)
        {
            buf2[j] = buf2[j] ^ buf1[j];
        }
        memcpy(buf3, buf4, 16);
    }

    if(decrypt_id(id, in.cip.data(), buf2))
        return 1;
    else
        return -1;

    return 1;
}

int
PunEncryption::encrypt_with_low_storage(DianaData &out, const std::string &id, PunEncryptionKey *key)
{
    unsigned char buf1[32], buf2[32], buf3[32], buf4[32];

    memset(buf2, 0, 16);
    memcpy(buf3, key->initial_key, 16);
    memcpy(buf4, buf3, 16);

    for (int i = 0; i < key->max_deletion; i++)
    {
        this->_punc_prf.Eval(buf4, out.tag, buf1);
        for (int j = 0; j < 16; j++)
        {
            buf2[j] = buf2[j] ^ buf1[j];
        }
        SHA256(buf3, 16, buf4);
        memcpy(buf3, buf4, 16);
    }

    encrypt_id(out.cip.data(), id, buf2);

    return 1;
}

int PunEncryption::incremental_punc(unsigned char *key, PunTag &tag, PuncturedKey *psk, unsigned char *key_next)
{
    //next key
    SHA256(key, 16, key_next);
    this->_punc_prf.Punc(key, tag, *psk);

    return 1;
}
