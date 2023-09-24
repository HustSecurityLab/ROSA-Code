#include <iostream>
#include <string>
#include "SSEServer.h"
#include <array>

extern "C"
{
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
}

using std::cerr;
using std::cout;
using std::endl;
using std::string;

Status SSEServer::Setup(ServerContext *ctx, const ROSE::SetupParam *param, ROSE::Stat *stat)
{
    rose_server.Setup();
    stat->set_stat(0);
    return grpc::Status::OK;
}

Status SSEServer::Update(ServerContext *ctx, const ROSE::Cipher *param,
                         ROSE::Stat *stat)
{
    rose_server.Save(param->l(), param->r(), param->d(), param->c());

    stat->set_stat(0);

    return grpc::Status::OK;
}

Status SSEServer::Search(ServerContext *ctx, const ROSE::Trapdoor *trapdoor, grpc::ServerWriter<ROSE::Fw> *writer)
{
    grpc::WriteOptions wopt;
    bool sent = false;
    std::vector<string> ciphers;

    wopt.clear_corked();

    KUPRF::init();
    rose_server.Search(ciphers, trapdoor->tpd_l(), trapdoor->tpd_t(), trapdoor->cip_l(), trapdoor->cip_r(),
                       trapdoor->cip_d(), trapdoor->cip_c());

    for (auto &itr : ciphers)
    {
        ROSE::Fw fw;

        fw.set_cip((char *)itr.data(), 32);
        while (!writer->Write(fw, wopt))
        {
        };
        if (!sent)
        {
            wopt.set_corked();
            sent = true;
        }
    }

    return grpc::Status::OK;
}

Status SSEServer::SearchRetId(ServerContext *ctx, grpc::ServerReader<ROSE::FileId> *reader, ROSE::Stat *stat)
{
    ROSE::FileId id;
    std::vector<string> ids;

    while (reader->Read(&id))
    {
        ids.emplace_back(id.file_id());
    }
    stat->set_stat(0);
    return grpc::Status::OK;
}

Status SSEServer::Backup(grpc::ServerContext *ctx, const ROSE::BackParam *param, ROSE::Stat *stat)
{
    rose_server.save_data(param->name());
    return grpc::Status::OK;
}

Status SSEServer::Load(grpc::ServerContext *ctx, const ROSE::BackParam *param, ROSE::Stat *stat)
{
    rose_server.load_data(param->name());
    return grpc::Status::OK;
}
Status SSEServer::GetStor(ServerContext *ctx, const ROSE::GetStorParam *param,
                          ROSE::SrvStor *reply)
{
    int srv_stor = rose_server.GetStor();
    reply->set_srv_stor(srv_stor);
    return grpc::Status::OK;
}