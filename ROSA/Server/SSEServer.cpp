#include <iostream>
#include <string>
#include "SSEServer.h"
#include "../CommonUtils.h"

extern "C"
{
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <unistd.h>
#include <string.h>
}

using std::cerr;
using std::cout;
using std::endl;
using std::string;

Status SSEServer::SetupORAM(ServerContext *context, const ROSA::SetupParam *param, ROSA::Stat *stat)
{
    oram_srv.Setup();
    stat->set_stat(0);
    return grpc::Status::OK;
}

Status SSEServer::ORAMBackup(ServerContext *context, const ROSA::BackParam *param, ROSA::Stat *stat)
{
    oram_srv.DumpData(string("rosa-oram-srv-") + param->name());
    stat->set_stat(0);
    return grpc::Status::OK;
}

Status SSEServer::ORAMLoad(ServerContext *context, const ROSA::BackParam *param, ROSA::Stat *stat)
{
    oram_srv.LoadData(string("rosa-oram-srv-") + param->name());
    stat->set_stat(0);
    return grpc::Status::OK;
}

Status SSEServer::ORAMGet(ServerContext *context, const ROSA::ORAMBlockNo *blocknos,
                          grpc::ServerWriter<ROSA::ORAMBlock> *writer)
{
    string block_data;
    WriteOptions wopt;
    bool sent = false;

    wopt.clear_corked();

    block_data.reserve(4096);

    for (auto &itr : blocknos->no())
    {
        ROSA::ORAMBlock block;
        oram_srv.Get(block_data, itr);
        block.set_no(itr);
        block.set_data(block_data);
        writer->Write(block, wopt);
        if (!sent)
        {
            wopt.set_corked();
            sent = true;
        }
    }
    return grpc::Status::OK;
}

Status SSEServer::ORAMPut(ServerContext *context, grpc::ServerReader<ROSA::ORAMBlock> *reader, ROSA::Stat *stat)
{
    ROSA::ORAMBlock block;

    while (reader->Read(&block))
    {
        oram_srv.Put(block.no(), block.data());
    }
    stat->set_stat(0);
    return grpc::Status::OK;
}

Status SSEServer::SetupRosa(grpc::ServerContext *context, const ROSA::SetupParam *param, ROSA::Stat *stat)
{
    rosa_srv.Setup();
    stat->set_stat(0);
    return grpc::Status::OK;
}

Status SSEServer::RosaAddCipher(grpc::ServerContext *context, const ROSA::RosaCipher *cip, ROSA::Stat *stat)
{
    vector<std::array<unsigned char, 32>> cips;
    std::array<unsigned char, 32> l_ = {};

    for (auto &itr : cip->cip())
    {
        memcpy(l_.data(), itr.c_str(), 32);
        cips.emplace_back(l_);
    }

    memcpy(l_.data(), cip->label().c_str(), 32);
    rosa_srv.SaveCipher(l_, cips);

    stat->set_stat(0);

    return grpc::Status::OK;
}

Status SSEServer::RosaSearch(grpc::ServerContext *context, const ROSA::RosaToken *token,
                             ROSA::Stat *stat)
{
    vector<string> result;
    vector<GGMNode> nodes;

    std::array<unsigned char, 32> K_s = {}, L_cache = {};

    for (auto &n : token->nodes())
    {
        GGMNode node(n.index(), n.level());
        memcpy(node.key, n.key().c_str(), 16);
        nodes.emplace_back(node);
    }

    memcpy(K_s.data(), token->ks().c_str(), 32);
    memcpy(L_cache.data(), token->l_cache().c_str(), 32);

    rosa_srv.Search(result, K_s, token->cnt_srch(), token->cnt_upd(), L_cache, nodes);

    stat->set_stat(result.size());

    return grpc::Status::OK;
}

Status SSEServer::RosaBackup(ServerContext *context, const ROSA::BackParam *param,
                             ROSA::Stat *stat)
{
    rosa_srv.dump_data(param->name());
    stat->set_stat(0);
    return grpc::Status::OK;
}

Status SSEServer::RosaLoad(ServerContext *context, const ROSA::BackParam *param,
                           ROSA::Stat *stat)
{
    rosa_srv.load_data(param->name());
    stat->set_stat(0);
    return grpc::Status::OK;
}

Status SSEServer::GetStor(ServerContext *ctx, const ROSA::GetStorParam *param,
                          ROSA::SrvStor *reply)
{
    int CDB_stor, Cache_stor, OMAP_stor;

    rosa_srv.GetStor(CDB_stor, Cache_stor);
    OMAP_stor = oram_srv.GetStor();

    reply->set_cdb_stor(CDB_stor);
    reply->set_cache_stor(Cache_stor);
    reply->set_omap_stor(OMAP_stor);

    return grpc::Status::OK;
}