#ifndef JANUSPP256_DIANACLIENT_H
#define JANUSPP256_DIANACLIENT_H

#include <map>
#include <string>
#include <unordered_map>
#include <vector>
#include <array>
#include "../pun_prf.h"
#include "../constrained_prf.h"

class DianaClient
{
public:
    DianaClient()= default;
    ~DianaClient()= default;
    int Setup();
    int update(std::array<unsigned char, 32> &label, const std::string& keyword);
    int trapdoor(const std::string& keyword, ConstrainedKey& trpdr_key, unsigned char *kw1_out);

    int GetStor();

    void dump_data(FILE *f_out);
    void load_data(FILE *f_in);

private:
    unsigned char key_master[16];
    std::map<std::string, unsigned int> keywords_conuter;
    void PRF_F_sha256(const char *keyword, unsigned int len, unsigned char *out);
};


#endif
