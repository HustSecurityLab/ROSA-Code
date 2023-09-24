#include "SSEClient.h"

#include <string>
#include <grpc++/grpc++.h>
#include <grpc/grpc.h>
#include <grpc++/server.h>
#include <grpc++/server_builder.h>
#include <grpc++/server_context.h>
#include "rosa.grpc.pb.h"
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
    ROSA::SetupParam req;
    ROSA::Stat reply;

    rosa_client.Setup();
    Status stat = stub_->SetupRosa(&ctx, req, &reply);
}

void SSEClient::Update(const std::string &keyword, const std::string &id, RosaOp op)
{
    std::array<unsigned char, 32> label={};
    std::vector<std::array<unsigned char, 32>> ciphers;
    grpc::ClientContext ctx;
    ROSA::RosaCipher cip;
    ROSA::Stat reply;

    rosa_client.Update(label, ciphers, keyword, id, op);

    if(!ciphers.empty())
    {
        std::string str;
        str.assign((char*)label.data(), label.size());
        cip.set_label(str);
        for(const auto &itr:ciphers)
        {
            str.assign((char*)itr.data(), itr.size());
            cip.add_cip(str);
        }
        Status stat = stub_->RosaAddCipher(&ctx, cip, &reply);
    }
}

int SSEClient::Search(const std::string &keyword)
{
    grpc::ClientContext ctx;
    ROSA::RosaToken token;
    ROSA::Stat stat;
    std::array<unsigned char, 32> K_s={}, L_cache={};
    int cnt_srch, cnt_upd;
    std::vector<GGMNode> nodes;
    std::string str;

    std::chrono::steady_clock::time_point begin, end;
    std::chrono::duration<double, std::micro> elapsed;

    begin = std::chrono::steady_clock::now();
    rosa_client.Trapdoor(K_s, cnt_srch, cnt_upd,L_cache,
                         nodes, keyword);
    end = std::chrono::steady_clock::now();
    elapsed = end - begin;
    bench_clnt_time += elapsed.count();

    if((cnt_upd > 0) || (cnt_srch > 0))
    {
        str.assign((char*)K_s.data(),K_s.size());
        token.set_ks(str);
        token.set_cnt_srch(cnt_srch);
        token.set_cnt_upd(cnt_upd);
        str.assign((char*)L_cache.data(), L_cache.size());
        token.set_l_cache(str);
        for(const GGMNode &n:nodes)
        {
            ROSA::GGMNode *_n = token.add_nodes();
            _n->set_index(n.index);
            _n->set_level(n.level);
            _n->set_key(n.key, 16);
        }
        Status status = stub_->RosaSearch(&ctx, token, &stat);

        return stat.stat();
    }
    return 0;
}

void SSEClient::BackupEDB(const std::string &filename)
{
    grpc::ClientContext ctx;
    ROSA::BackParam req;
    ROSA::Stat stat;

    rosa_client.dump_data(filename);

    req.set_name(filename + "-srv");
    Status status = stub_->RosaBackup(&ctx, req, &stat);
}

void SSEClient::LoadEDB(const std::string &filename)
{
    grpc::ClientContext ctx;
    ROSA::BackParam req;
    ROSA::Stat stat;

    rosa_client.load_data(filename );

    req.set_name(filename + "-srv");
    Status status = stub_->RosaLoad(&ctx, req, &stat);
}

void SSEClient::GetStor(int &clnt_stor, int &CDB_stor, int &Cache_stor, int &OMAP_stor)
{
    grpc::ClientContext ctx;
    ROSA::GetStorParam req;
    ROSA::SrvStor reply;

    clnt_stor = rosa_client.GetStor();

    Status status = stub_->GetStor(&ctx, req, &reply)        ;
    CDB_stor = reply.cdb_stor();
    Cache_stor = reply.cache_stor();
    OMAP_stor = reply.omap_stor();
}