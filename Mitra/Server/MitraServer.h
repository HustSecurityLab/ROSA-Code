#ifndef MITRA_MITRASERVER_H
#define MITRA_MITRASERVER_H

#include <vector>
#include <string>
#include <map>
#include <array>

class MitraServer
{
public:
    MitraServer() = default;

    ~MitraServer() = default;

    int Setup();

    int save(const std::array<unsigned char, 32> &label, const std::array<unsigned char, 32> &cipher);

    int search(std::vector<std::array<unsigned char, 32>> &Fw,
               const std::vector<std::array<unsigned char, 32>> &tlist);

    void dump_data(const std::string &filename="mitra_srv_data");
    void load_data(const std::string &filename="mitra_srv_data");

    int GetStor();

private:
    std::map<std::array<unsigned char, 32> , std::array<unsigned char, 32>> cipher_db;
};


#endif
