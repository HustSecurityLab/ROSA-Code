#ifndef ROSECLIENT_H
#define ROSECLIENT_H

#include <string>
#include <map>
#include <vector>
#include <array>
#include "../CommonUtils.h"
#include "../KUPRF.h"

//Key Size of KUPRF: 32
//Result Size of KUPRF: 33

using std::array;
using std::string;
using std::vector;

class ROSEClient
{
public:
    ROSEClient();

    ~ROSEClient();

    int Setup();

    int Update(string &L_out, string &cip_R, string &cip_D, string &cip_C, OP op,
               const string &keyword, const string &ind);

    int Trapdoor(std::string &tpd_L, std::string &tpd_T, std::string &cip_L,
                 std::string &cip_R, std::string &cip_D, std::string &cip_C, const std::string &keyword);

    int Decrypt(vector<string> &out, const string &keyword, const vector<array<unsigned char, 32>> &in);

    void save_data(const std::string &fname = "rose_client_data.dat");

    void load_data(const std::string &fname = "rose_client_data.dat");

    int GetStor();

private:
    unsigned char Kse[16];
    std::map<string, string> LastId;
    std::map<string, string> LastK, LastS, LastR;
    std::map<string, OP> LastOp;

    int Enc_id(array<unsigned char, 32> &C_out, const string &id);

    int Dec_id(string &id_out, const array<unsigned char, 32> &C_in);

};


#endif
