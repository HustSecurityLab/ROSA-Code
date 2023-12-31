#ifndef ROSE_ROSESERVER_H
#define ROSE_ROSESERVER_H

#include "../CommonUtils.h"
#include <vector>
#include <string>
#include <memory>
#include <map>
#include <array>
#include "../KUPRF.h"

using std::array;
using std::string;
using std::vector;

struct Cipher
{
    unsigned char R[16];
    unsigned char D[1 + 32 * 2 + 33];
    unsigned char C[32];
};

class ROSEServer
{
public:
    ROSEServer() = default;

    ~ROSEServer();

    int Setup();

    int Save(const std::string &L, const std::string &R, const std::string &D, const std::string &C);

    int Search(std::vector<std::string> &result, const std::string &tpd_L, const std::string &tpd_T,
               const std::string &cip_L, const std::string &cip_R, const std::string &cip_D, const std::string &cip_C);

    void save_data(const std::string &fname = "rose_server_data.dat");

    void load_data(const std::string &fname = "rose_server_data.dat");

    int GetStor();

private:
    std::map<std::string, Cipher *> _store;
};

#endif
