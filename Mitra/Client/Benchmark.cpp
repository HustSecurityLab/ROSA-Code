#include "Benchmark.h"
#include <chrono>
#include <iostream>
#include <string>
#include <map>
#include <unordered_map>
#include <vector>
#include <set>
#include <vector>
#include <grpc/grpc.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>
#include <iostream>

#include "SSEClient.h"

extern "C"
{
#include <openssl/rand.h>
#include <unistd.h>
}

double bench_clnt_time = 0;

using namespace std;

Benchmark::Benchmark(const std::string &filename, const std::string &_name, const std::string &_addr)
{
    read_data_from_file_(filename);
    this->name = _name;
    this->addr = _addr;
}

void Benchmark::read_data_from_file_(const std::string &filename)
{
    global_filename = filename;
    FILE *f_in = fopen(filename.c_str(), "r");
    int keyword_num;
    char word[256], id[256];

    total_entry_num = 0;
    data_to_encrypt.clear();

    fscanf(f_in, "%d\n", &keyword_num);
    for (int i = 0; i < keyword_num; i++)
    {
        fscanf(f_in, "%s\n", word);
        if (data_to_encrypt.find(word) == data_to_encrypt.end())
        {
            vector<string> _t;
            data_to_encrypt[word] = _t;
        }

        vector<string> &_v = data_to_encrypt[word];

        int file_num = 0;
        fscanf(f_in, "%d\n", &file_num);
        for (int j = 0; j < file_num; j++)
        {
            fscanf(f_in, "%s\n", id);
            _v.emplace_back(string(id));
            plane_db.emplace_back(pair<string, string>(string(word), string(id)));
            total_entry_num += 1;
        }
    }
    fclose(f_in);
}

void Benchmark::benchmark_test_DataUpdate()
{
    string L, tag;
    vector<string> ciph;

    auto channel = grpc::CreateCustomChannel(this->addr, grpc::InsecureChannelCredentials(), get_channel_args());

    SSEClient sse_client(channel, this->addr);
    chrono::steady_clock::time_point begin, end;
    chrono::duration<double, std::micro> elapsed;
    double total_add = 0, total_del = 0, clnt_add, clnt_del;
    vector<pair<string, string>> data_to_delete;
    int num_data_to_del = 40000;
    int updated_num = 0;

    sse_client.Setup();

    //bench_clnt_time = 0;
    begin = chrono::steady_clock::now();
    for (auto &itr : data_to_encrypt)
    {
        for (auto &id : itr.second)
        {
            sse_client.Update(itr.first, id, op_add);
            updated_num ++;
            if(updated_num % 20000 == 0)
                cerr << "test_DataUpdate: already updated " << updated_num << " pairs..." << endl;
        }
    }
    end = chrono::steady_clock::now();
    elapsed = end - begin;
    total_add += elapsed.count();
    //clnt_add = bench_clnt_time;

    sse_client.BackupEDB(this->name);
    random_select_delected_entries(data_to_delete, num_data_to_del);
    //bench_clnt_time = 0;
    begin = chrono::steady_clock::now();
    for (auto &itr : data_to_delete)
    {
        sse_client.Update(itr.first, itr.second, op_del);
    }
    end = chrono::steady_clock::now();
    elapsed = end - begin;
    total_del += elapsed.count();
    //clnt_del = bench_clnt_time;

    cout << "Encryption with op = add time cost: " << endl;
    cout << "\tTotally " << total_entry_num << " records, total " << total_add << " us" << endl;
    cout << "\taverage time " << total_add / total_entry_num << " us" << endl << endl;
    //cout << "\taverage client time " << clnt_add / total_entry_num << " us" << endl
    //     << endl;

    cout << "Encryption with op = del time cost: " << endl;
    cout << "\tTotally " << num_data_to_del << " records, total " << total_del << " us" << endl;
    cout << "\taverage time " << total_del / num_data_to_del << " us" << endl << endl;
    //cout << "\taverage client time " << clnt_del / num_data_to_del << " us" << endl
    //     << endl;
}

void Benchmark::random_select_file_identifiers_(vector<std::string> &ids, set<int> &found_index, const string &keyword,
                                                int num_of_id)
{
    int cur_number = 0, index;

    ids.clear();

    if (num_of_id >= data_to_encrypt[keyword].size())
    {
        for (int i = 0; i < total_entry_num; i++)
            ids.emplace_back(data_to_encrypt[keyword][i]);
    }
    else
    {
        while (cur_number < num_of_id)
        {
            RAND_bytes((unsigned char *)&index, sizeof(int));
            index = index % data_to_encrypt[keyword].size();
            if (index < 0)
                index = -index;
            if (found_index.find(index) == found_index.end())
            {
                found_index.emplace(index);
                cur_number++;
                ids.emplace_back(data_to_encrypt[keyword][index]);
            }
        }
    }
}

void Benchmark::random_select_delected_entries(std::vector<pair<string, string>> &entries, int num_data_to_delete)
{
    int cur_number = 0, index;
    set<int> found_index;

    entries.clear();

    if (num_data_to_delete >= total_entry_num)
    {
        for (int i = 0; i < total_entry_num; i++)
            entries.emplace_back(plane_db[i]);
    }
    else
    {
        while (cur_number < num_data_to_delete)
        {
            RAND_bytes((unsigned char *)&index, sizeof(int));
            index = index % total_entry_num;
            if (index < 0)
                index = -index;
            if (found_index.find(index) == found_index.end())
            {
                found_index.emplace(index);
                cur_number++;
                entries.emplace_back(plane_db[index]);
            }
        }
    }
}

void Benchmark::benchmark_test_Search()
{
    chrono::steady_clock::time_point begin, end;
    chrono::duration<double, std::micro> elapsed;
    double total_time = 0;
    vector<string> plaintexts;

    cout << "Start searching..." << endl;

    for (auto &itr : data_to_encrypt)
    {
        auto channel = grpc::CreateCustomChannel(this->addr, grpc::InsecureChannelCredentials(),
                                                 get_channel_args());

        SSEClient sse_client(channel, this->addr);
        sse_client.Setup();
        sse_client.LoadEDB(this->name);

        plaintexts.clear();
        plaintexts.reserve(150000);
        total_time = 0;
        bench_clnt_time = 0;

        begin = chrono::steady_clock::now();
        sse_client.Search(plaintexts, itr.first);
        end = chrono::steady_clock::now();
        elapsed = end - begin;
        total_time = elapsed.count();

        cout << "Searching with Mitra for keyword: " << itr.first << endl;
        cout << "\tTotally find " << plaintexts.size() << " records and the last file ID is "
             << plaintexts[plaintexts.size() - 1] << endl;
        cout << "\tTime cost of the whole search phase is " << fixed << total_time << " us" << endl;
        cout << "\tTime cost of the client is " << fixed << bench_clnt_time << " us" << endl;
        cout << "\tAverage time cost is " << fixed << total_time / plaintexts.size() << " us" << endl;
    }
}

void Benchmark::benchmark_test_delete(const std::string &keyword_to_delete)
{
    chrono::steady_clock::time_point begin, end;
    chrono::duration<double, std::micro> elapsed;
    vector<string> plaintexts, id_to_del, Ls, Tags;
    vector<vector<string>> ciphers;
    set<int> id_index;
    double total_time = 0;

    cout << "Start Deleting..." << endl;

    for (int por = 0; por < 91; por += 10)
    {
        auto channel = grpc::CreateCustomChannel(this->addr, grpc::InsecureChannelCredentials(),
                                                 get_channel_args());

        SSEClient sse_client(channel, this->addr);
        sse_client.Setup();
        sse_client.LoadEDB(this->name);

        id_to_del.clear();
        id_index.clear();

        if (por != 0)
        {
            random_select_file_identifiers_(id_to_del, id_index, keyword_to_delete,
                                            int(por / 100.0 * data_to_encrypt[keyword_to_delete].size()));
            for (auto &itr : id_to_del)
                sse_client.Update(keyword_to_delete, itr, op_del);
        }

        plaintexts.clear();
        plaintexts.reserve(150000);
        total_time = 0;
        bench_clnt_time = 0;

        begin = chrono::steady_clock::now();
        sse_client.Search(plaintexts, keyword_to_delete);
        end = chrono::steady_clock::now();
        elapsed = end - begin;
        total_time = elapsed.count();

        cout << "Searching with Deletion with Mitra for keyword: " << keyword_to_delete << endl;
        cout << "Delete portion: " << por * 0.01 << ", deleted "
             << id_to_del.size() << endl;
        cout << "\tTotally find " << plaintexts.size() << " records and the last file ID is "
             << plaintexts[plaintexts.size() - 1] << endl;
        cout << "\tTime cost of the whole search phase is " << fixed << total_time << " us" << endl;
        cout << "\tTime cost of the client is " << fixed << bench_clnt_time << " us" << endl;
        cout << "\tAverage time cost is " << fixed << total_time / plaintexts.size() << " us" << endl;
    }
}

void Benchmark::get_client_stor()
{
    vector<string> result;
    int keyword_num = 0;
    int clnt_stor, srv_stor;
    auto channel = grpc::CreateCustomChannel(this->addr, grpc::InsecureChannelCredentials(),
                                             get_channel_args());
    SSEClient sse_client(channel, this->addr);

    sse_client.Setup();

    while(keyword_num <= 5000)
    {
        sse_client.Update("keyword" + to_string(keyword_num), "file-"+to_string(keyword_num), op_add);
        keyword_num += 1;

        if(keyword_num % 250 == 0)
        {
            sse_client.GetStor(clnt_stor, srv_stor);
            cout << "Keyword number: " << keyword_num << ", Client Storage: " << clnt_stor << " Bytes" << endl;
        }
    }
}

void Benchmark::get_srv_stor(int entry_num)
{
    vector<string> result;
    int clnt_stor, srv_stor;
    auto channel = grpc::CreateCustomChannel(this->addr, grpc::InsecureChannelCredentials(),
                                             get_channel_args());
    SSEClient sse_client(channel, this->addr);

    sse_client.Setup();

    for(int i=0;i<entry_num;i++)
    {
        sse_client.Update("keyword", "file-"+to_string(i), op_add);
    }
    sse_client.GetStor(clnt_stor, srv_stor);
    cout << "Entry number: " << entry_num << ", server storage: " << srv_stor << " Bytes." << endl;
    sse_client.Search(result, "keyword");
    sse_client.GetStor(clnt_stor, srv_stor);
    cout << "After search, server storage size: " << srv_stor << " Bytes" << endl << endl;
}

void Benchmark::benchmark_stor()
{
    cout << "----------------[Client Storage of MITRA]------------------" << endl;
    get_client_stor();
    cout << "----------------[Server Storage of MITRA]------------------" << endl;
    for(int i=25000;i<500001;i+=25000)
        get_srv_stor(i);
}