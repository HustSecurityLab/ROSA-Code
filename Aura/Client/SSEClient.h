#ifndef SSECLIENT_H
#define SSECLIENT_H

#include "AuraClient.h"
#include <string>
#include <vector>
#include <map>
#include "aura.grpc.pb.h"

#undef  GRPC_DEFAULT_MAX_RECV_MESSAGE_LENGTH
#define GRPC_DEFAULT_MAX_RECV_MESSAGE_LENGTH (64 * 1024 * 1024)

class SSEClient
{
public:
    SSEClient() = delete;

    SSEClient(std::shared_ptr<grpc::ChannelInterface> channel,
              const std::string &srv_addr = "127.0.0.1:54324") :
            stub_(AURA::AURASSE::NewStub(channel))
    {
    }

    void Setup();

    void Update(const std::string &keyword, const std::string &id, OP op);

    int Search(const std::string &keyword);

    void BackupEDB(const std::string &filename = "Aura-backup");

    void LoadEDB(const std::string &filename = "Aura-backup");

    void GetStor(int &clnt_stor, int &EDB_stor, int &Cache_stor);

private:
    std::unique_ptr<AURA::AURASSE::Stub> stub_;
    AuraClient aura_client;
};

#endif
