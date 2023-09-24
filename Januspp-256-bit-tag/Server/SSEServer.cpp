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

Status SSEServer::Setup(ServerContext *context, const JANUSPP::SetupParam *param,
                        JANUSPP::Stat *stat)
{
    januspp_server.Setup();
    stat->set_stat(0);
    return grpc::Status::OK;
}

Status SSEServer::Add(ServerContext *context, const JANUSPP::AddCipher *cipher,
                      JANUSPP::Stat *stat)
{
    std::array<unsigned char, 32> label;
    DianaData payload;

    memcpy(label.data(), cipher->label().c_str(), 32);
    memcpy(payload.cip.data(), cipher->cipher().c_str(), payload.cip.size());
    memcpy(payload.tag.get_data_ptr(), cipher->tag_data().c_str(), payload.tag.size());

    this->januspp_server.SaveCipher(label, payload);

    stat->set_stat(0);
    return grpc::Status::OK;
}

Status SSEServer::Delete(ServerContext *context, const JANUSPP::DelCipher *del_cipher,
                         JANUSPP::Stat *stat)
{
    std::array<unsigned char, 32> label;
    DianaDataDel payload;

    memcpy(label.data(), del_cipher->label().c_str(), label.size());
    payload.key.type = static_cast<PuncturedKeyType>(del_cipher->key().type());
    for (int i = 0; i < del_cipher->key().keydata().size(); i++)
    {
        std::array<unsigned char, 16> keydata;
        Path path;

        memcpy(keydata.data(), del_cipher->key().keydata()[i].c_str(), 16);
        memcpy(path.path_data.get_data_ptr(), del_cipher->key().tag_prefix()[i].path_data().c_str(), path.path_data.size());
        memcpy(path.mask.get_data_ptr(), del_cipher->key().tag_prefix()[i].mask().c_str(), path.mask.size());

        payload.key.keydata.emplace_back(keydata);
        payload.key.tag_prefix.emplace_back(path);
    }
    memcpy(payload.tag.get_data_ptr(), del_cipher->tag_data().c_str(), payload.tag.size());

    januspp_server.DeleteCipher(label, payload);

    stat->set_stat(0);
    return grpc::Status::OK;
}

Status SSEServer::Search(ServerContext *context, const JANUSPP::Trapdoor *trapdoor,
                         JANUSPP::Stat *stat)
{
    std::array<unsigned char, 16> msk_out, kw1, kw1_del;
    std::array<unsigned char, 32> tkn;
    ConstrainedKey trpd, trpd_del;
    std::vector<std::string> ret;

    memcpy(msk_out.data(), trapdoor->msk_out().c_str(), msk_out.size());
    memcpy(tkn.data(), trapdoor->tkn().c_str(), tkn.size());
    trpd.current_permitted = trapdoor->trpd().current_permitted();
    trpd.max_permitted = trapdoor->trpd().max_permitted();

    for (int i = 0; i < trapdoor->trpd().permitted_keys().size(); i++)
    {
        ConstrainedKeyData keydata;

        memcpy(keydata.key_data.data(), trapdoor->trpd().permitted_keys()[i].key_data().c_str(), keydata.key_data.size());
        keydata.level = trapdoor->trpd().permitted_keys()[i].level();
        keydata.path = trapdoor->trpd().permitted_keys()[i].path();

        trpd.permitted_keys.emplace_back(keydata);
    }
    memcpy(kw1.data(), trapdoor->kw1().c_str(), kw1.size());

    trpd_del.current_permitted = trapdoor->trpd_del().current_permitted();
    trpd_del.max_permitted = trapdoor->trpd_del().max_permitted();

    for (int i = 0; i < trapdoor->trpd_del().permitted_keys().size(); i++)
    {
        ConstrainedKeyData keydata;

        memcpy(keydata.key_data.data(), trapdoor->trpd_del().permitted_keys()[i].key_data().c_str(), keydata.key_data.size());
        keydata.level = trapdoor->trpd_del().permitted_keys()[i].level();
        keydata.path = trapdoor->trpd_del().permitted_keys()[i].path();

        trpd_del.permitted_keys.emplace_back(keydata);
    }

    memcpy(kw1_del.data(), trapdoor->kw1_del().c_str(), kw1_del.size());

    januspp_server.Search(ret, msk_out, tkn, trpd, kw1, trpd_del, kw1_del);

    stat->set_stat(ret.size());
    return grpc::Status::OK;
}

Status SSEServer::Backup(ServerContext *context, const JANUSPP::BackParam *param,
                         JANUSPP::Stat *stat)
{
    januspp_server.dump_data(param->name());
    stat->set_stat(0);
    return grpc::Status::OK;
}

Status SSEServer::Load(ServerContext *context, const JANUSPP::BackParam *param,
                       JANUSPP::Stat *stat)
{
    januspp_server.load_data(param->name());
    stat->set_stat(0);
    return grpc::Status::OK;
}

Status SSEServer::GetStor(ServerContext *ctx, const JANUSPP::GetStorParam *param,
                          JANUSPP::SrvStor *stor)
{
    int srv_stor, srv_del_stor, oldres_stor;

    januspp_server.GetStor(srv_stor, srv_del_stor, oldres_stor);

    stor->set_srv_stor(srv_stor);
    stor->set_srv_del_stor(srv_del_stor);
    stor->set_oldres_stor(oldres_stor);

    return grpc::Status::OK;
}