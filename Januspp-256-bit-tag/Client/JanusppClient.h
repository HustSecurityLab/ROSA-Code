#ifndef JANUSPP256_JANUSPPCLIENT_H
#define JANUSPP256_JANUSPPCLIENT_H

#include <vector>
#include <string>
#include <map>
#include <array>
#include "../pun_encryption.h"
#include "DianaClient.h"
#include "../CommonUtils.h"

class JanusPPClient
{
public:
    JanusPPClient() = default;

    ~JanusPPClient();

    int Setup();

    int Add(std::array<unsigned char, 32> &label, DianaData &payload, const std::string &keyword, const std::string &ind);

    int Delete(std::array<unsigned char, 32> &label, DianaDataDel &payload, const std::string &keyword, const std::string &ind);

    int trapdoor(std::array<unsigned char, 16> &msk_out, std::array<unsigned char, 32> &tkn, ConstrainedKey &trpd,
                 std::array<unsigned char, 16> &kw1,ConstrainedKey &trpd_del, std::array<unsigned char, 16> &kw1_del,
                 const std::string &keyword);

    PunTag generate_tag(const std::string &keyword, const std::string &ind);

    int GetStor();

    void dump_data(const std::string &filename = "januspp_clnt_data");

    void load_data(const std::string &filename = "januspp_clnt_data");

private:
    unsigned char kt[16];
    unsigned char ks[16];
    std::map<std::string, int> sc;
    std::map<std::string, int> del;
    std::map<std::string, std::array<unsigned char, 16>> msk;
    std::unordered_map<std::string, std::array<unsigned char, 16>> psk;
    int deleting_support;
    DianaClient diana_clnt;
    DianaClient diana_clnt_del;

    int _init_keyword_state(const std::string &keyword);

    int _prf_f(const std::string &keyword, const std::string &ind, unsigned char *data);
};

#endif
