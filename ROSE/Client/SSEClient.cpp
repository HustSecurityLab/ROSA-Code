#include "SSEClient.h"

#include <string>
#include <grpc++/grpc++.h>
#include <grpc/grpc.h>
#include <grpc++/server.h>
#include <grpc++/server_builder.h>
#include <grpc++/server_context.h>
#include "rose.grpc.pb.h"
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
    ROSE::SetupParam req;
    ROSE::Stat reply;

    rose_client.Setup();
    Status stat = stub_->Setup(&ctx, req, &reply);
}

void SSEClient::Update(const std::string &keyword, const std::string &id, OP op)
{
    grpc::ClientContext ctx;
    ROSE::Stat reply;
    ROSE::Cipher cip;
    string L, R, D, C;
    std::chrono::steady_clock::time_point begin, end;
    std::chrono::duration<double, std::micro> elapsed;

    // begin = std::chrono::steady_clock::now();
    rose_client.Update(L, R, D, C, op, keyword, id);
    // end = std::chrono::steady_clock::now();
    // elapsed = end - begin;
    // bench_clnt_time += elapsed.count();

    cip.set_l(L);
    cip.set_r(R);
    cip.set_d(D);
    cip.set_c(C);

    Status stat = stub_->Update(&ctx, cip, &reply);
}

void SSEClient::Search(std::vector<std::string> &result, const std::string &keyword)
{
    grpc::ClientContext ctx, ctx1;
    ROSE::Trapdoor trpdr;
    ROSE::Fw ret;
    ROSE::Stat stat;
    std::vector<std::array<unsigned char, 32>> ret_cip;
    string L, C, tpd_L, tpd_T, R, D;
    std::chrono::steady_clock::time_point begin, end;
    std::chrono::duration<double, std::micro> elapsed;
    grpc::WriteOptions wopt;
    bool sent = false;

    wopt.clear_corked();

    begin = std::chrono::steady_clock::now();
    rose_client.Trapdoor(tpd_L, tpd_T, L, R, D, C, keyword);
    end = std::chrono::steady_clock::now();
    elapsed = end - begin;
    bench_clnt_time += elapsed.count();

    trpdr.set_tpd_l(tpd_L);
    trpdr.set_tpd_t(tpd_T);
    trpdr.set_cip_l(L);
    trpdr.set_cip_r(R);
    trpdr.set_cip_d(D);
    trpdr.set_cip_c(C);

    std::unique_ptr<grpc::ClientReader<ROSE::Fw>> reader(stub_->Search(&ctx, trpdr));

    while (reader->Read(&ret))
    {
        std::array<unsigned char, 32> _ret = {};
        memcpy(_ret.data(), ret.cip().c_str(), _ret.size());
        ret_cip.emplace_back(_ret);
    }

    begin = std::chrono::steady_clock::now();
    rose_client.Decrypt(result, keyword, ret_cip);
    end = std::chrono::steady_clock::now();
    elapsed = end - begin;
    bench_clnt_time += elapsed.count();

    std::unique_ptr<grpc::ClientWriter<ROSE::FileId>> writer(stub_->SearchRetId(&ctx1, &stat));

    for (auto &itr : result)
    {
        ROSE::FileId id;
        id.set_file_id(itr);
        while (!writer->Write(id, wopt))
        {
        };
        if (!sent)
        {
            wopt.set_corked();
            sent = true;
        }
    }
    writer->WritesDone();
    writer->Finish();
}

void SSEClient::BackupEDB(const std::string &filename)
{
    grpc::ClientContext ctx;
    ROSE::BackParam req;
    ROSE::Stat stat;

    rose_client.save_data(filename);

    req.set_name(filename + "-srv");
    Status status = stub_->Backup(&ctx, req, &stat);
}

void SSEClient::LoadEDB(const std::string &filename)
{
    grpc::ClientContext ctx;
    ROSE::BackParam req;
    ROSE::Stat stat;

    rose_client.load_data(filename);
    req.set_name(filename + "-srv");
    Status status = stub_->Load(&ctx, req, &stat);
}

void SSEClient::GetStor(int &clnt_stor, int &srv_stor)
{
    clnt_stor = srv_stor = 0;

    grpc::ClientContext ctx;
    ROSE::GetStorParam req;
    ROSE::SrvStor reply;

    clnt_stor = rose_client.GetStor();

    Status status = stub_->GetStor(&ctx, req, &reply);
    srv_stor = reply.srv_stor();
}