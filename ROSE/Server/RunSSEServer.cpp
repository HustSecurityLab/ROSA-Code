#include <iostream>
#include <string>
#include <vector>
#include <map>
#include "SSEServer.h"
#include <grpc/grpc.h>
#include <grpcpp/create_channel.h>
#include <grpcpp/security/server_credentials.h>
#include <grpcpp/server.h>
#include <grpcpp/server_builder.h>
#include <grpcpp/server_context.h>
#include "../CommonUtils.h"

using namespace std;

void RunServer()
{
    std::string server_address("127.0.0.1:54324");
    SSEServer service;

    grpc::ServerBuilder builder;

    builder.AddChannelArgument(GRPC_ARG_KEEPALIVE_TIME_MS, 1500);
    builder.AddChannelArgument(GRPC_ARG_KEEPALIVE_TIMEOUT_MS, 6000);
    builder.AddChannelArgument(GRPC_ARG_HTTP2_MAX_PINGS_WITHOUT_DATA, 0);
    builder.AddChannelArgument(GRPC_ARG_HTTP2_MAX_PING_STRIKES, 0);
    builder.AddChannelArgument(GRPC_ARG_HTTP2_WRITE_BUFFER_SIZE, WRITE_BUFFER_SIZE);
    builder.AddChannelArgument(GRPC_ARG_HTTP2_MAX_FRAME_SIZE, 64*1024);
    builder.AddChannelArgument(GRPC_ARG_HTTP2_STREAM_LOOKAHEAD_BYTES, 1024*1024);
    builder.SetMaxMessageSize(-1);
    builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
    builder.RegisterService(&service);
    std::unique_ptr<grpc::Server> server(builder.BuildAndStart());

    cout << "ROSE server running..." << endl;

    server->Wait();
}

int main(int argc, char*argv[])
{
    KUPRF::init();
    RunServer();
    KUPRF::clean();

    return 0;
}