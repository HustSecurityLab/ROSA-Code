#ifndef SSESERVER_H
#define SSESERVER_H


#include "aura.grpc.pb.h"

#include <string>
#include <vector>
#include "AuraServer.h"
#include "../CommonUtils.h"

using grpc::Status;
using grpc::ServerContext;
using grpc::WriteOptions;
using AURA::AURASSE;

class SSEServer : public AURASSE::Service
{
public:

    Status SetupAura(ServerContext *context, const AURA::SetupParam *param,
                     AURA::Stat *stat) override;

    Status AuraAddCipher(ServerContext *context, const AURA::AuraCipher* cip,
                         AURA::Stat *stat) override;

    Status AuraSearch(ServerContext *context, const AURA::AuraToken *token,
                      AURA::Stat *stat) override;

    Status AuraBackup(ServerContext *context, const AURA::BackParam *param,
                      AURA::Stat *stat) override;

    Status AuraLoad(ServerContext *context, const AURA::BackParam *param,
                    AURA::Stat *stat) override;

    Status GetStor(ServerContext *context, const AURA::GetStorParam *param, AURA::SrvStor *reply) override;

private:
    AuraServer aura_server;
};


#endif
