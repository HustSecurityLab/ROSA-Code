#ifndef JANUSPP256_DIANASERVER_H
#define JANUSPP256_DIANASERVER_H

#include <map>
#include <string>
#include <vector>
#include <array>
#include "../pun_prf.h"
#include "../constrained_prf.h"
#include "../CommonUtils.h"

class DianaServer
{
public:
    DianaServer()= default;
    ~DianaServer();
    int Setup();
    int Save(const std::array<unsigned char, 32> &label, const DianaData &payload);
    int Save(const std::array<unsigned char, 32> &label, const DianaDataDel &payload);
    int Search(ConstrainedKey& trpder_key, unsigned char *kw1, std::vector<DianaData>& out);
    int Search(ConstrainedKey& trpder_key, unsigned char *kw1, std::vector<DianaDataDel>& out);

    int GetStor();

    void dump_data(FILE *f_out);
    void load_data(FILE *f_in);
private:
    std::map<std::array<unsigned char, 32>, DianaData> cipher_store;
    std::map<std::array<unsigned char, 32>, DianaDataDel> psk_store;
};

#endif
