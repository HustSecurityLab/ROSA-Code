#ifndef MITRA_SSECLIENT_H
#define MITRA_SSECLIENT_H


#include "MitraClient.h"
#include <string>
#include <array>
#include <vector>
#include <map>
#include "mitra.grpc.pb.h"

#undef  GRPC_DEFAULT_MAX_RECV_MESSAGE_LENGTH
#define GRPC_DEFAULT_MAX_RECV_MESSAGE_LENGTH (64 * 1024 * 1024)

class SSEClient
{
public:
    SSEClient() = delete;

    SSEClient(std::shared_ptr<grpc::ChannelInterface> channel,
              const std::string &srv_addr = "127.0.0.1:54324") :
            stub_(MITRA::MITRASSE::NewStub(channel))
    {
    }

    void Setup();

    void Update(const std::string &keyword, const std::string &id, OP op);

    void Search(std::vector<std::string> &result, const std::string &keyword);

    void BackupEDB(const std::string &filename = "mitra-backup");

    void LoadEDB(const std::string &filename = "mitra-backup");

    void GetStor(int &clnt_stor, int &srv_stor);

private:
    std::unique_ptr<MITRA::MITRASSE::Stub> stub_;
    MitraClient mitra_client;
};


#endif
