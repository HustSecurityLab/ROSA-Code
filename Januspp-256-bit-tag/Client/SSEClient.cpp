#include "SSEClient.h"

#include <string>
#include <grpc++/grpc++.h>
#include <grpc/grpc.h>
#include <grpc++/server.h>
#include <grpc++/server_builder.h>
#include <grpc++/server_context.h>
#include "januspp.grpc.pb.h"
#include <iostream>
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
    JANUSPP::SetupParam req;
    JANUSPP::Stat reply;

    januspp_client.Setup();
    Status stat = stub_->Setup(&ctx, req, &reply);
}

void SSEClient::Update(const std::string &keyword, const std::string &id, OP op)
{
    grpc::ClientContext ctx;
    JANUSPP::Stat reply;
    std::chrono::steady_clock::time_point begin, end;
    std::chrono::duration<double, std::micro> elapsed;

    if (op == op_add)
    {
        std::array<unsigned char, 32> label;
        DianaData payload;
        JANUSPP::AddCipher cip;
        std::string tmp;

        //begin = std::chrono::steady_clock::now();
        januspp_client.Add(label, payload, keyword, id);
        //end = std::chrono::steady_clock::now();
        //elapsed = end - begin;
        //bench_clnt_time += elapsed.count();

        tmp.assign((char *) label.data(), label.size());
        cip.set_label(tmp);

        tmp.assign((char *) payload.cip.data(), payload.cip.size());
        cip.set_cipher(tmp);

        tmp.assign((char *) payload.tag.get_data_ptr(), payload.tag.size());
        cip.set_tag_data(tmp);

        Status stat = stub_->Add(&ctx, cip, &reply);
    }
    else
    {
        std::array<unsigned char, 32> label;
        DianaDataDel payload;
        JANUSPP::DelCipher cip;
        JANUSPP::PuncturedKey *pkey = new JANUSPP::PuncturedKey();
        std::string tmp;

        //begin = std::chrono::steady_clock::now();
        januspp_client.Delete(label, payload, keyword, id);
        //end = std::chrono::steady_clock::now();
        //elapsed = end - begin;
        //bench_clnt_time += elapsed.count();

        tmp.assign((char *) label.data(), label.size());
        cip.set_label(tmp);

        pkey->set_type(payload.key.type);

        for (int i = 0; i < payload.key.keydata.size(); i++)
        {
            std::string keydata, path_data, path_mask;
            PuncturedKey &key = payload.key;

            keydata.assign((char *) key.keydata[i].data(), key.keydata[i].size());
            path_data.assign((char *) key.tag_prefix[i].path_data.get_data_ptr(), key.tag_prefix[i].path_data.size());
            path_mask.assign((char *) key.tag_prefix[i].mask.get_data_ptr(), key.tag_prefix[i].mask.size());

            pkey->add_keydata(keydata);
            JANUSPP::Path *path = pkey->add_tag_prefix();

            path->set_path_data(path_data);
            path->set_mask(path_mask);
        }
        cip.set_allocated_key(pkey);
        cip.set_tag_data((char *) payload.tag.get_data_ptr(), payload.tag.size());

        Status stat = stub_->Delete(&ctx, cip, &reply);
    }
}

int SSEClient::Search(const std::string &keyword)
{
    grpc::ClientContext ctx;
    JANUSPP::Trapdoor trpdr;
    JANUSPP::Stat stat;
    JANUSPP::ConstrainedKey *s_trpd = new JANUSPP::ConstrainedKey();
    JANUSPP::ConstrainedKey *s_trpd_del = new JANUSPP::ConstrainedKey();
    std::array<unsigned char, 16> msk_out, kw1, kw1_del;
    std::array<unsigned char, 32> tkn;
    ConstrainedKey trpd, trpd_del;
    std::string tmp;
    std::chrono::steady_clock::time_point begin, end;
    std::chrono::duration<double, std::micro> elapsed;

    begin = std::chrono::steady_clock::now();
    int tpd_ok = januspp_client.trapdoor(msk_out, tkn, trpd, kw1, trpd_del, kw1_del, keyword);
    end = std::chrono::steady_clock::now();
    elapsed = end - begin;
    bench_clnt_time += elapsed.count();

    if ( tpd_ok == 0)
        return 0;

    tmp.assign((char *) msk_out.data(), msk_out.size());
    trpdr.set_msk_out(tmp);

    tmp.assign((char *) tkn.data(), tkn.size());
    trpdr.set_tkn(tmp);

    s_trpd->set_current_permitted(trpd.current_permitted);
    s_trpd->set_max_permitted(trpd.max_permitted);
    for (int i = 0; i < trpd.permitted_keys.size(); i++)
    {
        JANUSPP::ConstrainedKeyData *kd = s_trpd->add_permitted_keys();
        ConstrainedKeyData &keydata = trpd.permitted_keys[i];

        tmp.assign((char *) keydata.key_data.data(), keydata.key_data.size());
        kd->set_key_data(tmp);

        kd->set_level(keydata.level);
        kd->set_path(keydata.path);
    }
    trpdr.set_allocated_trpd(s_trpd);

    tmp.assign((char *) kw1.data(), kw1.size());
    trpdr.set_kw1(tmp);

    s_trpd_del->set_current_permitted(trpd_del.current_permitted);
    s_trpd_del->set_max_permitted(trpd_del.max_permitted);
    for (int i = 0; i < trpd_del.permitted_keys.size(); i++)
    {
        JANUSPP::ConstrainedKeyData *kd = s_trpd_del->add_permitted_keys();
        ConstrainedKeyData &keydata = trpd_del.permitted_keys[i];

        tmp.assign((char *) keydata.key_data.data(), keydata.key_data.size());
        kd->set_key_data(tmp);

        kd->set_level(keydata.level);
        kd->set_path(keydata.path);
    }
    trpdr.set_allocated_trpd_del(s_trpd_del);

    tmp.assign((char *) kw1_del.data(), kw1_del.size());
    trpdr.set_kw1_del(tmp);

    Status status = stub_->Search(&ctx, trpdr, &stat);

    return stat.stat();
}

void SSEClient::BackupEDB(const std::string &filename)
{
    grpc::ClientContext ctx;
    JANUSPP::BackParam req;
    JANUSPP::Stat stat;

    januspp_client.dump_data(filename);

    req.set_name(filename + "-srv");
    Status status = stub_->Backup(&ctx, req, &stat);
}

void SSEClient::LoadEDB(const std::string &filename)
{
    grpc::ClientContext ctx;
    JANUSPP::BackParam req;
    JANUSPP::Stat stat;

    januspp_client.load_data(filename);
    req.set_name(filename + "-srv");
    Status status = stub_->Load(&ctx, req, &stat);
}

void SSEClient::GetStor(int &clnt_stor, int &srv_stor, int &srv_del_stor, int &oldres_stor)
{
    grpc::ClientContext ctx;
    JANUSPP::GetStorParam req;
    JANUSPP::SrvStor reply;

    clnt_stor = januspp_client.GetStor();
    Status status = stub_->GetStor(&ctx, req, &reply);
    srv_stor = reply.srv_stor();
    srv_del_stor = reply.srv_del_stor();
    oldres_stor = reply.oldres_stor();
}