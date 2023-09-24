#ifndef MITRA_MITRACLIENT_H
#define MITRA_MITRACLIENT_H

#include <vector>
#include <string>
#include <array>
#include <map>
#include "../CommonUtils.h"

class MitraClient
{
public:
    MitraClient() = default;

    ~MitraClient() = default;

    int Setup();

    int update(std::array<unsigned char, 32> &label, std::array<unsigned char, 32> &cipher,
    const std::string &keyword, const std::string &ind, OP op);

    int search_stage1(std::vector<std::array<unsigned char, 32>> &tlist, const std::string &keyword);

    int search_stage2(std::vector<std::string> &search_ret, const std::string& keyword,
                      const std::vector<std::array<unsigned char, 32>> &Fw);

    void dump_data(const std::string &filename="mitra_clnt_data");
    void load_data(const std::string &filename="mitra_clnt_data");

    int GetStor();

private:
    unsigned char k_master[16];
    std::map<std::string, unsigned int> FileCnt;
    int _prf_gen_label(const std::string &keyword, unsigned int c, unsigned char *label);
    int _prf_gen_ciphertext(const std::string &keyword, unsigned int c, unsigned char *ciphertext);
};


#endif
