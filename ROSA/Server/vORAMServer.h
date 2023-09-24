#ifndef VORAMSERVER_H
#define VORAMSERVER_H

#include <map>
#include <string>

class vORAMServer
{
public:
    vORAMServer() = default;
    ~vORAMServer() = default;

    void Setup();

    void Get(std::string &encrypted_bucket, int id);

    void Put(int id, const std::string &encrypted_bucket);

    void DumpData(const std::string &filename="ROSA-vORAM-back");
    void LoadData(const std::string &filename="ROSA-vORAM-back");

    int GetStor();

private:
    std::map<int, std::string> store;
};

#endif