#ifndef VORAMBUCKET_H
#define VORAMBUCKET_H

#include <string>

extern "C"
{
#include <stdlib.h>
#include <string.h>
}

class Bucket
{
public:
    int nodesize, keylen, lenlen, idlen, remaining;
    unsigned char *data_;

    Bucket();
    Bucket(const Bucket &_bucket);
    Bucket(int nodesize, int keylen, int lenlen, int idlen);
    Bucket(Bucket &&_b) noexcept;
    ~Bucket();

    Bucket &operator=(const Bucket & _b);
    Bucket &operator=(Bucket &&_b) noexcept;

    void Setup(int nodesize, int keylen, int lenlen, int idlen);

    unsigned char *key1();
    unsigned char *key2();
    unsigned char *id(int blob_no);
    int len(int blob_no);
    unsigned char *blob(int blob_no);
    int len(unsigned char *id);
    unsigned char *blob(unsigned char *id);

    int append_blob(unsigned char *id, unsigned char *data, int len);

    void to_encrypted_string(std::string &out,const unsigned char *key, int keylen);

    void from_encrypted_string(const std::string &in, const unsigned char *key, int keylen);
private:
    unsigned char *first_empty_id();
};

#endif