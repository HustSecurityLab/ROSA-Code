#include "SSEClient.h"

#include <string>
#include <grpc++/grpc++.h>
#include <grpc/grpc.h>
#include <grpc++/server.h>
#include <grpc++/server_builder.h>
#include <grpc++/server_context.h>
#include "mitra.grpc.pb.h"
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
    MITRA::SetupParam req;
    MITRA::Stat reply;

    mitra_client.Setup();
    Status stat = stub_->Setup(&ctx, req, &reply);
}

void SSEClient::Update(const std::string &keyword, const std::string &id, OP op)
{
    std::array<unsigned char, 32> l = {}, c = {};
    grpc::ClientContext ctx;
    MITRA::Cipher req;
    MITRA::Stat reply;
    std::chrono::steady_clock::time_point begin, end;
    std::chrono::duration<double, std::micro> elapsed;

    //begin = std::chrono::steady_clock::now();
    mitra_client.update(l, c, keyword, id, op);
    //end = std::chrono::steady_clock::now();
    //elapsed = end - begin;
    //bench_clnt_time += elapsed.count();

    req.set_label((char *) l.data(), l.size());
    req.set_cipher((char *) c.data(), c.size());
    Status stat = stub_->Update(&ctx, req, &reply);
}

void SSEClient::Search(std::vector<std::string> &result, const std::string &keyword)
{
    grpc::ClientContext ctx, ctx1;
    std::vector<std::array<unsigned char, 32>> tlists, Fw;
    MITRA::Fw fw;
    MITRA::Stat stat;
    grpc::WriteOptions wopt;
    bool sent = false;
    std::chrono::steady_clock::time_point begin, end;
    std::chrono::duration<double, std::micro> elapsed;

    wopt.clear_corked();

    result.clear();

    begin = std::chrono::steady_clock::now();
    mitra_client.search_stage1(tlists, keyword);
    end = std::chrono::steady_clock::now();
    elapsed = end - begin;
    bench_clnt_time += elapsed.count();

    std::unique_ptr<grpc::ClientReaderWriter<MITRA::Tokens, MITRA::Fw>> rw(stub_->Search(&ctx));

    for (int i = 0; i < tlists.size(); i++)
    {
        MITRA::Tokens t;
        t.set_label((char *) tlists[i].data(), tlists[i].size());
        while(!rw->Write(t, wopt)) {};
        if(!sent)
        {
            sent = true;
            wopt.set_corked();
        }
    }
    rw->WritesDone();

    while (rw->Read(&fw))
    {
        std::array<unsigned char, 32> fw_ = {};

        memcpy(fw_.data(), fw.cip().c_str(), 32);
        Fw.emplace_back(fw_);
    }

    rw->Finish();

    begin = std::chrono::steady_clock::now();
    mitra_client.search_stage2(result, keyword, Fw);
    end = std::chrono::steady_clock::now();
    elapsed = end - begin;
    bench_clnt_time += elapsed.count();

    sent = false;
    wopt.clear_corked();
    std::unique_ptr<grpc::ClientWriter<MITRA::FileId>> writer(stub_->SearchRetId(&ctx1, &stat));

    for(auto &itr : result)
    {
        MITRA::FileId id;
        id.set_file_id(itr);
        while(!writer->Write(id, wopt)) {};
        if(!sent)
        {
            wopt.set_corked();
            sent = true;
        }
    }
    writer->WritesDone();
    writer->Finish();
}

void SSEClient::LoadEDB(const std::string &filename)
{
    grpc::ClientContext ctx;
    MITRA::BackParam req;
    MITRA::Stat reply;

    mitra_client.load_data(filename);
    req.set_name(filename + "-srv");
    Status stat = stub_->Load(&ctx, req, &reply);
}

void SSEClient::BackupEDB(const std::string &filename)
{
    grpc::ClientContext ctx;
    MITRA::BackParam req;
    MITRA::Stat reply;

    mitra_client.dump_data(filename);
    req.set_name(filename + "-srv");
    Status stat = stub_->Backup(&ctx, req, &reply);
}

void SSEClient::GetStor(int &clnt_stor, int &srv_stor)
{
    clnt_stor = srv_stor = 0;

    grpc::ClientContext ctx;
    MITRA::GetStorParam req;
    MITRA::SrvStor reply;

    clnt_stor = mitra_client.GetStor();
    Status stat = stub_->GetStor(&ctx, req, &reply);
    srv_stor = reply.srv_stor();
}