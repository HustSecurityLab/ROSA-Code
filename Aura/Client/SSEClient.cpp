#include "SSEClient.h"

#include <string>
#include <grpc++/grpc++.h>
#include <grpc/grpc.h>
#include <grpc++/server.h>
#include <grpc++/server_builder.h>
#include <grpc++/server_context.h>
#include "aura.grpc.pb.h"
#include <iostream>
#include <chrono>
#include <unordered_map>

extern "C"
{
#include "unistd.h"
}

using grpc::Channel;
using grpc::ClientAsyncResponseReader;
using grpc::ClientContext;
using grpc::CompletionQueue;
using grpc::Status;
using std::cout;
using std::endl;

extern double bench_clnt_time;

void SSEClient::Setup()
{
    grpc::ClientContext ctx;
    AURA::SetupParam req;
    AURA::Stat reply;

    aura_client.Setup();

    Status stat = stub_->SetupAura(&ctx, req, &reply);
}

void SSEClient::Update(const std::string &keyword, const std::string &id, OP op)
{
    std::array<unsigned char, 32> label = {}, tag = {};
    std::vector<std::array<unsigned char, 32>> ciphers;
    grpc::ClientContext ctx;
    AURA::AuraCipher cip;
    AURA::Stat reply;
    std::chrono::steady_clock::time_point begin, end;
    std::chrono::duration<double, std::micro> elapsed;

    //begin = std::chrono::steady_clock::now();
    aura_client.Update(label, tag, ciphers, keyword, id, op);
    //end = std::chrono::steady_clock::now();
    //elapsed = end - begin;
    //bench_clnt_time += elapsed.count();

    if (!ciphers.empty())
    {
        std::string str;

        str.assign((char *) label.data(), label.size());
        cip.set_label(str);

        str.assign((char *) tag.data(), tag.size());
        cip.set_tag(str);

        for (const auto &itr: ciphers)
        {
            str.assign((char *) itr.data(), itr.size());
            cip.add_cip(str);
        }
        Status stat = stub_->AuraAddCipher(&ctx, cip, &reply);
    }
}

int SSEClient::Search(const std::string &keyword)
{
    grpc::ClientContext ctx;
    AURA::AuraToken token;
    AURA::Stat stat;
    std::array<unsigned char, 32> trapdoor, cache_token;
    std::vector<GGMNode> nodes;
    std::string str;
    std::chrono::steady_clock::time_point begin, end;
    std::chrono::duration<double, std::micro> elapsed;

    begin = std::chrono::steady_clock::now();
    aura_client.Trapdoor(trapdoor, cache_token, nodes, keyword);
    end = std::chrono::steady_clock::now();
    elapsed = end - begin;
    bench_clnt_time += elapsed.count();

    str.assign((char *) trapdoor.data(), trapdoor.size());
    token.set_trapdoor(str);

    str.assign((char *) cache_token.data(), cache_token.size());
    token.set_cache_token(str);
    for (const GGMNode &n: nodes)
    {
        AURA::GGMNode *_n = token.add_nodes();
        _n->set_index(n.index);
        _n->set_level(n.level);
        _n->set_key(n.key, 16);
    }
    Status status = stub_->AuraSearch(&ctx, token, &stat);

    return stat.stat();

}

void SSEClient::BackupEDB(const std::string &filename)
{
    grpc::ClientContext ctx;
    AURA::BackParam req;
    AURA::Stat stat;

    aura_client.dump_data(filename);

    req.set_name(filename + "-srv");
    Status status = stub_->AuraBackup(&ctx, req, &stat);
}

void SSEClient::LoadEDB(const std::string &filename)
{
    grpc::ClientContext ctx;
    AURA::BackParam req;
    AURA::Stat stat;

    aura_client.load_data(filename);

    req.set_name(filename + "-srv");
    Status status = stub_->AuraLoad(&ctx, req, &stat);
}

void SSEClient::GetStor(int &clnt_stor, int &EDB_stor, int &Cache_stor)
{
    grpc::ClientContext ctx;
    AURA::GetStorParam req;
    AURA::SrvStor reply;

    clnt_stor = aura_client.GetStor();

    Status status = stub_->GetStor(&ctx, req, &reply);
    EDB_stor = reply.edb_stor();
    Cache_stor = reply.cache_stor();


}