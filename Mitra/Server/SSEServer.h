#ifndef MITRA_SSESERVER_H
#define MITRA_SSESERVER_H

#include "mitra.grpc.pb.h"
#include <string>
#include <vector>
#include "MitraServer.h"

using grpc::ServerContext;
using grpc::Status;
using MITRA::MITRASSE;

class SSEServer : public MITRASSE::Service
{
public:
    Status Setup(ServerContext *ctx, const MITRA::SetupParam *param,
                 MITRA::Stat *stat) override;

    Status Update(ServerContext *ctx, const MITRA::Cipher *param,
                  MITRA::Stat *stat) override;

    Status Search(ServerContext *ctx, grpc::ServerReaderWriter<MITRA::Fw, MITRA::Tokens> *rw) override;

    Status SearchRetId(ServerContext *ctx, grpc::ServerReader<MITRA::FileId> *reader, MITRA::Stat *stat) override;

    Status Backup(ServerContext *ctx, const MITRA::BackParam *param,
                  MITRA::Stat *stat) override;

    Status Load(ServerContext *ctx, const MITRA::BackParam *param,
                MITRA::Stat *stat) override;

    Status GetStor(ServerContext *ctx, const MITRA::GetStorParam *param,
                   MITRA::SrvStor *reply) override;

private:
    MitraServer mitra_server;
};

#endif
