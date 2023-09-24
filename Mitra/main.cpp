#include <iostream>
#include <iostream>
#include <vector>
#include <string>
#include <array>
#include "client/MitraClient.h"
#include "server/MitraServer.h"

using namespace std;

int test_mitra_correctness()
{
    std::array<unsigned char, 32> l={},v={};
    char buf1[512];
    vector<array<unsigned char, 32>> tlist, Fw;
    vector<string> ret;

    MitraClient mitra_clnt;
    MitraServer mitra_srv;

    mitra_clnt.Setup();
    mitra_srv.Setup();

    tlist.reserve(300000);
    ret.reserve(300000);
    Fw.reserve(300000);

    for (int i = 0; i < 100000; i++)
    {
        sprintf(buf1, "0001--%d", i);
        mitra_clnt.update(l,v,"abc", buf1, Mitra_Add);
        mitra_srv.save(l, v);
    }

    for (int i = 8000; i < 100000; i++)
    {
        sprintf(buf1, "0001--%d", i);
        mitra_clnt.update(l, v, "abc", buf1, Mitra_Del);
        mitra_srv.save(l, v);
    }

    mitra_clnt.search_stage1(tlist, "abc");
    mitra_srv.search(Fw,tlist);
    mitra_clnt.search_stage2(ret, "abc", Fw);

    for (const auto &a:ret)
        cout << a << endl;

    cout << "---------------------------------" << endl;
    cout << "result size: " << ret.size() << endl;

    Fw.clear();
    ret.clear();
    tlist.clear();

    mitra_clnt.dump_data();
    mitra_clnt.Setup();
    mitra_clnt.load_data();
    mitra_srv.dump_data();
    mitra_srv.Setup();
    mitra_srv.load_data();

    mitra_clnt.search_stage1(tlist, "abc");
    mitra_srv.search(Fw,tlist);
    mitra_clnt.search_stage2(ret, "abc", Fw);

    for (const auto &a:ret)
        cout << a << endl;

    cout << "---------------------------------" << endl;
    cout << "result size: " << ret.size() << endl;

    return 1;
}


int main()
{
    test_mitra_correctness();
    return 0;
}