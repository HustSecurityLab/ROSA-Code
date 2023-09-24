#ifndef ROSE_SSESERVER_H
#define ROSE_SSESERVER_H

#include "rose.grpc.pb.h"
#include <string>
#include <vector>
#include "ROSEServer.h"

using grpc::ServerContext;
using grpc::Status;
using ROSE::ROSESSE;

class SSEServer : public ROSESSE::Service
{
public:
    Status Setup(ServerContext *ctx, const ROSE::SetupParam *param,
                 ROSE::Stat *stat) override;

    Status Update(ServerContext *ctx, const ROSE::Cipher *param,
                  ROSE::Stat *stat) override;

    Status Search(ServerContext *ctx, const ROSE::Trapdoor *trpdr, grpc::ServerWriter<ROSE::Fw> *writer) override;

    Status SearchRetId(ServerContext *ctx, grpc::ServerReader<ROSE::FileId> *reader, ROSE::Stat *stat) override;

    Status Backup(ServerContext *ctx, const ROSE::BackParam *param,
                  ROSE::Stat *stat) override;

    Status Load(ServerContext *ctx, const ROSE::BackParam *param,
                ROSE::Stat *stat) override;

    Status GetStor(ServerContext *ctx, const ROSE::GetStorParam *param,
                   ROSE::SrvStor *reply) override;

private:
    ROSEServer rose_server;
};

#endif
