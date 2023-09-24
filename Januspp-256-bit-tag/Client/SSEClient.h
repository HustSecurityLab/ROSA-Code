#ifndef JANUSPP256_SSECLIENT_H
#define JANUSPP256_SSECLIENT_H

#include "JanusppClient.h"
#include <string>
#include <vector>
#include <map>
#include "januspp.grpc.pb.h"
#include "../CommonUtils.h"

#undef GRPC_DEFAULT_MAX_RECV_MESSAGE_LENGTH
#define GRPC_DEFAULT_MAX_RECV_MESSAGE_LENGTH (64 * 1024 * 1024)

class SSEClient
{
public:
    SSEClient() = delete;

    SSEClient(std::shared_ptr<grpc::ChannelInterface> channel,
              const std::string &srv_addr = "127.0.0.1:54324") : stub_(JANUSPP::JANUSPPSSE::NewStub(channel))
    {
    }

    void Setup();

    void Update(const std::string &keyword, const std::string &id, OP op);

    int Search(const std::string &keyword);

    void BackupEDB(const std::string &filename = "JANUSPP-256-backup");

    void LoadEDB(const std::string &filename = "JANUSPP-256-backup");

    void GetStor(int &clnt_stor, int &srv_stor, int &srv_del_stor, int &oldres_stor);

private:
    std::unique_ptr<JANUSPP::JANUSPPSSE::Stub> stub_;
    JanusPPClient januspp_client;
};

#endif