#ifndef JANUSPP256_JANUSPPSERVER_H
#define JANUSPP256_JANUSPPSERVER_H

#include <vector>
#include <string>
#include <map>
#include <array>
#include "../pun_encryption.h"
#include "DianaServer.h"
#include "../CommonUtils.h"

class JanusPPServer
{
public:
    JanusPPServer() = default;

    ~JanusPPServer() = default;

    int Setup();

    int SaveCipher(const std::array<unsigned char, 32> &label, const DianaData &payload);

    int DeleteCipher(const std::array<unsigned char, 32> &label, const DianaDataDel &payload);

    //Just one time search
    int Search(std::vector<std::string> &output,std::array<unsigned char, 16> &msk_out,
               std::array<unsigned char, 32> &tkn, ConstrainedKey &trpd, std::array<unsigned char, 16> &kw1,
               ConstrainedKey &trpd_del, std::array<unsigned char, 16> &kw1_del);

    void GetStor(int &srv_stor, int &srv_del_stor, int &oldres_stor);

    void dump_data(const std::string &filename = "januspp_srv_data");

    void load_data(const std::string &filename = "januspp_srv_data");

private:
    DianaServer diana_srv;
    DianaServer diana_srv_del;
    std::map<std::array<unsigned char, 32>, std::map<std::array<unsigned char, 32>, std::string>> OldRes;
};


#endif
