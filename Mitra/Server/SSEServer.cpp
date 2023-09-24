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

Status SSEServer::Setup(grpc::ServerContext *ctx, const MITRA::SetupParam *param, MITRA::Stat *stat)
{
    mitra_server.Setup();
    stat->set_stat(0);
    return grpc::Status::OK;
}

Status SSEServer::Update(grpc::ServerContext *ctx, const MITRA::Cipher *param, MITRA::Stat *stat)
{
    std::array<unsigned char, 32> l = {}, c = {};

    memcpy(l.data(), param->label().c_str(), 32);
    memcpy(c.data(), param->cipher().c_str(), 32);

    mitra_server.save(l, c);

    return grpc::Status::OK;
}

Status SSEServer::Search(grpc::ServerContext *ctx, grpc::ServerReaderWriter<MITRA::Fw, MITRA::Tokens> *rw)
{
    std::vector<std::array<unsigned char, 32>> tlists, fws;
    MITRA::Tokens tk;
    grpc::WriteOptions wopt;
    bool sent = false;

    wopt.clear_corked();

    while (rw->Read(&tk))
    {
        std::array<unsigned char, 32> tk_ = {};
        memcpy(tk_.data(), tk.label().c_str(), 32);
        tlists.emplace_back(tk_);
    }
    mitra_server.search(fws, tlists);

    for (auto &itr : fws)
    {
        MITRA::Fw fw;

        fw.set_cip((char *)itr.data(), 32);
        while (!rw->Write(fw, wopt))
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

Status SSEServer::SearchRetId(ServerContext *ctx, grpc::ServerReader<MITRA::FileId> *reader, MITRA::Stat *stat)
{
    MITRA::FileId id;
    std::vector<string> ids;

    while (reader->Read(&id))
    {
        ids.emplace_back(id.file_id());
    }
    stat->set_stat(0);
    return grpc::Status::OK;
}

Status SSEServer::Backup(grpc::ServerContext *ctx, const MITRA::BackParam *param, MITRA::Stat *stat)
{
    mitra_server.dump_data(param->name());
    return grpc::Status::OK;
}

Status SSEServer::Load(grpc::ServerContext *ctx, const MITRA::BackParam *param, MITRA::Stat *stat)
{
    mitra_server.load_data(param->name());
    return grpc::Status::OK;
}

Status SSEServer::GetStor(ServerContext *ctx, const MITRA::GetStorParam *param,
                          MITRA::SrvStor *reply)
{
    int srv_stor = 0;

    srv_stor = mitra_server.GetStor();
    reply->set_srv_stor(srv_stor);

    return grpc::Status::OK;
}