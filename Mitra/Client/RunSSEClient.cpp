#include "SSEClient.h"
#include <vector>
#include <grpc/grpc.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>
#include <iostream>
#include <string>
#include <chrono>
#include "Benchmark.h"

using std::cout;
using std::endl;
using std::vector;

using namespace std;

const std::string addr = "127.0.0.1:54324";

void RunBenchmark()
{
    Benchmark bench("sse-data-large", "data-large", addr);
    cout << "Start testing DataUpdate..." << endl;
    bench.benchmark_test_DataUpdate();
    cout << "Start testing Search..." << endl;
    bench.benchmark_test_Search();
    cout << "Start testing Delete..." << endl;
    bench.benchmark_test_delete("anchor");
    cout << "Start testing Storage..." << endl;
    bench.benchmark_stor();
}

void test_DSSE()
{
    vector<string> result;
    auto channel = grpc::CreateCustomChannel(addr, grpc::InsecureChannelCredentials(),
                                             get_channel_args());
    SSEClient sse_client(channel, addr);

    for(int i=0;i<100;i++)
        sse_client.Update("abc", "file-"+to_string(i), op_add);
    for(int i=0;i<50;i++)
        sse_client.Update("def", "file-"+to_string(i), op_add);

    sse_client.Search(result, "abc");
    cout << "find " << result.size() << " results when searching for abc" << endl;
    result.clear();
    sse_client.Search(result, "def");
    cout << "find " << result.size() << " results when searching for def" << endl;
}

int main(int argc, char *argv[])
{
    //RunBenchmark();
    test_DSSE();
    return 0;

}