#include <stdio.h>
#include "../CommonUtils.h"
#include "vORAMServer.h"
#include <mutex>

static std::mutex mu_;

void vORAMServer::Setup()
{
    store.clear();
}

void vORAMServer::Get(std::string &encrypted_bucket, int id)
{
    encrypted_bucket = store[id];
}

void vORAMServer::Put(int id, const std::string &encrypted_bucket)
{
    mu_.lock();
    store[id] = encrypted_bucket;
    mu_.unlock();
}

void vORAMServer::DumpData(const std::string &filename)
{
    FILE *f_out = fopen((filename + "-srv").c_str(), "wb");
    size_t size = this->store.size();

    fwrite(&size, sizeof(size), 1, f_out);
    for (auto &itr : this->store)
    {
        fwrite(&(itr.first), sizeof(itr.first), 1, f_out);
        save_string(f_out, itr.second);
    }
    fclose(f_out);
}

void vORAMServer::LoadData(const std::string &filename)
{
    FILE *f_in = fopen((filename + "-srv").c_str(), "rb");
    size_t size;
    std::string str;
    int no;

    this->store.clear();

    fread(&size, sizeof(size), 1, f_in);
    for (size_t i = 0; i < size; i++)
    {
        fread(&no, sizeof(no), 1, f_in);
        load_string(str, f_in);
        this->store[no] = str;
    }
    fclose(f_in);
}

int vORAMServer::GetStor()
{
    int ret = 0;

    for (const auto &itr : store)
    {
        ret += sizeof(itr.first);
        ret += itr.second.size();
    }

    return ret;
}