#ifndef SSECLIENT_H
#define SSECLIENT_H

#include "ROSAClient.h"
#include <string>
#include <vector>
#include <map>
#include "rosa.grpc.pb.h"

#undef GRPC_DEFAULT_MAX_RECV_MESSAGE_LENGTH
#define GRPC_DEFAULT_MAX_RECV_MESSAGE_LENGTH (64 * 1024 * 1024)

class SSEClient
{
public:
    SSEClient() = delete;

    SSEClient(std::shared_ptr<grpc::ChannelInterface> channel,
              int omap_cap = 1000000,
              const std::string &srv_addr = "127.0.0.1:54324") : stub_(ROSA::ROSASSE::NewStub(channel)), rosa_client(omap_cap, srv_addr)
    {
    }

    void Setup();

    void Update(const std::string &keyword, const std::string &id, RosaOp op);

    int Search(const std::string &keyword);

    void BackupEDB(const std::string &filename = "ROSA-backup");

    void LoadEDB(const std::string &filename = "ROSA-backup");

    void GetStor(int &clnt_stor, int &CDB_stor, int &Cache_stor, int &OMAP_stor);

private:
    std::unique_ptr<ROSA::ROSASSE::Stub> stub_;
    ROSAClient rosa_client;
};

#endif