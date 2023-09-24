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

Status SSEServer::SetupAura(grpc::ServerContext *context, const AURA::SetupParam *param, AURA::Stat *stat)
{
    aura_server.Setup();
    stat->set_stat(0);
    return grpc::Status::OK;
}

Status SSEServer::AuraAddCipher(grpc::ServerContext *context, const AURA::AuraCipher *cip, AURA::Stat *stat)
{
    vector<std::array<unsigned char, 32>> cips;
    std::array<unsigned char, 32> label = {}, tag = {};

    for (auto &itr: cip->cip())
    {
        memcpy(label.data(), itr.c_str(), 32);
        cips.emplace_back(label);
    }

    memcpy(label.data(), cip->label().c_str(), 32);
    memcpy(tag.data(), cip->tag().c_str(), 32);
    aura_server.SaveCipher(label, tag, cips);

    stat->set_stat(0);

    return grpc::Status::OK;
}

Status SSEServer::AuraSearch(grpc::ServerContext *context, const AURA::AuraToken *token,
                             AURA::Stat *stat)
{
    vector<string> result;
    vector<GGMNode> nodes;

    std::array<unsigned char, 32> trapdoor = {}, cache_token = {};

    for (auto &n: token->nodes())
    {
        GGMNode node(n.index(), n.level());
        memcpy(node.key, n.key().c_str(), 16);
        nodes.emplace_back(node);
    }

    memcpy(trapdoor.data(), token->trapdoor().c_str(), 32);
    memcpy(cache_token.data(), token->cache_token().c_str(), 32);

    aura_server.Search(result, trapdoor, cache_token, nodes);

    stat->set_stat(result.size());

    return grpc::Status::OK;
}

Status SSEServer::AuraBackup(ServerContext *context, const AURA::BackParam *param,
                             AURA::Stat *stat)
{
    aura_server.dump_data(param->name());
    stat->set_stat(0);
    return grpc::Status::OK;
}

Status SSEServer::AuraLoad(ServerContext *context, const AURA::BackParam *param,
                           AURA::Stat *stat)
{
    aura_server.load_data(param->name());
    stat->set_stat(0);
    return grpc::Status::OK;
}

Status SSEServer::GetStor(ServerContext *context, const AURA::GetStorParam *param, AURA::SrvStor *reply)
{
    int EDB_stor, Cache_stor;

    aura_server.GetStor(EDB_stor, Cache_stor);

    reply->set_edb_stor(EDB_stor);
    reply->set_cache_stor(Cache_stor);

    return grpc::Status::OK;
}