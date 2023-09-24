#ifndef SSESERVER_H
#define SSESERVER_H

#include "rosa.grpc.pb.h"

#include <string>
#include <vector>
#include "vORAMServer.h"
#include "ROSAServer.h"
#include "../CommonUtils.h"

using grpc::ServerContext;
using grpc::Status;
using grpc::WriteOptions;
using ROSA::ROSASSE;

class SSEServer : public ROSASSE::Service
{
public:
    Status SetupORAM(ServerContext *context, const ROSA::SetupParam *param,
                     ROSA::Stat *stat) override;

    Status ORAMBackup(ServerContext *context, const ROSA::BackParam *param,
                      ROSA::Stat *stat) override;

    Status ORAMLoad(ServerContext *context, const ROSA::BackParam *param,
                    ROSA::Stat *stat) override;

    Status ORAMGet(ServerContext *context, const ROSA::ORAMBlockNo *blocknos,
                   grpc::ServerWriter<ROSA::ORAMBlock> *writer) override;

    Status ORAMPut(ServerContext *context, grpc::ServerReader<ROSA::ORAMBlock> *reader,
                   ROSA::Stat *stat) override;

    Status SetupRosa(ServerContext *context, const ROSA::SetupParam *param,
                     ROSA::Stat *stat) override;

    Status RosaAddCipher(ServerContext *context, const ROSA::RosaCipher *cip,
                         ROSA::Stat *stat) override;

    Status RosaSearch(ServerContext *context, const ROSA::RosaToken *token,
                      ROSA::Stat *stat) override;

    Status RosaBackup(ServerContext *context, const ROSA::BackParam *param,
                      ROSA::Stat *stat) override;

    Status RosaLoad(ServerContext *context, const ROSA::BackParam *param,
                    ROSA::Stat *stat) override;

    Status GetStor(ServerContext *context, const ROSA::GetStorParam *param,
                   ROSA::SrvStor *reply) override;

private:
    vORAMServer oram_srv;
    ROSAServer rosa_srv;
};

#endif