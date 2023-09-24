#ifndef SSECLIENT_H
#define SSECLIENT_H


#include "ROSEClient.h"
#include <string>
#include <vector>
#include <map>
#include "rose.grpc.pb.h"
#include "../CommonUtils.h"

#undef  GRPC_DEFAULT_MAX_RECV_MESSAGE_LENGTH
#define GRPC_DEFAULT_MAX_RECV_MESSAGE_LENGTH (64 * 1024 * 1024)

class SSEClient
{
public:
    SSEClient() = delete;

    SSEClient(std::shared_ptr<grpc::ChannelInterface> channel,
              const std::string &srv_addr = "127.0.0.1:54324") :
            stub_(ROSE::ROSESSE::NewStub(channel))
    {
    }

    void Setup();

    void Update(const std::string &keyword, const std::string &id, OP op);

    void Search(std::vector<std::string> &result, const std::string &keyword);

    void GetStor(int &clnt_stor, int &srv_stor);

    void BackupEDB(const std::string &filename = "JANUSPP-128-backup");

    void LoadEDB(const std::string &filename = "JANUSPP-128-backup");

private:
    std::unique_ptr<ROSE::ROSESSE::Stub> stub_;
    ROSEClient rose_client;
};


#endif
