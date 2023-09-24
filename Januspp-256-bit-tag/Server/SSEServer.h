#ifndef JANUSPP256_SSESERVER_H
#define JANUSPP256_SSESERVER_H

#include "januspp.grpc.pb.h"

#include <string>
#include <vector>
#include "JanusppServer.h"
#include "../CommonUtils.h"

using grpc::ServerContext;
using grpc::Status;
using grpc::WriteOptions;

class SSEServer : public JANUSPP::JANUSPPSSE::Service
{
public:
    Status Setup(ServerContext *context, const JANUSPP::SetupParam *param,
                 JANUSPP::Stat *stat) override;

    Status Add(ServerContext *context, const JANUSPP::AddCipher *cipher,
               JANUSPP::Stat *stat) override;

    Status Delete(ServerContext *context, const JANUSPP::DelCipher *del_cipher,
                  JANUSPP::Stat *stat) override;

    Status Search(ServerContext *context, const JANUSPP::Trapdoor *trapdoor,
                  JANUSPP::Stat *stat) override;

    Status Backup(ServerContext *context, const JANUSPP::BackParam *param,
                  JANUSPP::Stat *stat) override;

    Status Load(ServerContext *context, const JANUSPP::BackParam *param,
                JANUSPP::Stat *stat) override;

    Status GetStor(ServerContext *ctx, const JANUSPP::GetStorParam *param,
                   JANUSPP::SrvStor *stor) override;

private:
    JanusPPServer januspp_server;
};

#endif