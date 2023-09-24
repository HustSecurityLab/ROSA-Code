cmake_minimum_required(VERSION 3.0.0)
project(ROSA VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 17)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/protobuf)

find_package(Protobuf REQUIRED)
find_package(GRPC REQUIRED)

set(PROTOS
        ${CMAKE_CURRENT_SOURCE_DIR}/protobuf/rosa.proto)

set(PROTO_SRC_DIR ${CMAKE_CURRENT_BINARY_DIR}/protobuf)
file(MAKE_DIRECTORY ${PROTO_SRC_DIR})
include_directories(${PROTO_SRC_DIR} ${GRPC_INCLUDE_DIR} ${PROTOBUF_INCLUDE_DIR})

protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_SRC_DIR} ${PROTOS})
grpc_generate_cpp(GRPC_SRCS GRPC_HDRS ${PROTO_SRC_DIR} ${PROTOS})

add_executable(SSEServer
        Server/RunSSEServer.cpp
        Server/SSEServer.cpp
        Server/SSEServer.h
        Server/vORAMServer.cpp
        Server/vORAMServer.h
        ${PROTO_SRCS}
        ${PROTO_HDRS}
        ${GRPC_SRCS}
        ${GRPC_HDRS}
        CommonUtils.cpp
        CommonUtils.h
        GGM/GGMTree.cpp
        GGM/GGMTree.h
        GGM/GGMNode.h
        Server/ROSAServer.cpp
        Server/ROSAServer.h
        BF/BloomFilter.h
        BF/Hash/SpookyV2.cpp
        BF/Hash/SpookyV2.h)

target_link_libraries(SSEServer -lcrypto gRPC::grpc++ protobuf::libprotobuf)

add_executable(SSEClient
        Client/vORAMBucket.cpp
        Client/vORAMBucket.h
        Client/vORAMClient.cpp
        Client/vORAMClient.h
        Client/HIRBTreeNode.cpp
        Client/HIRBpathStat.cpp
        Client/HIRBpathStat.h
        Client/HIRBTreeNode.h
        Client/HIRBTree.cpp
        Client/HIRBTree.h
        Client/ROSAClient.cpp
        Client/ROSAClient.h
        Client/SSEClient.cpp
        Client/SSEClient.h
        Client/Benchmark.h
        Client/Benchmark.cpp
        Client/RunSSEClient.cpp
        ${PROTO_SRCS}
        ${PROTO_HDRS}
        ${GRPC_SRCS}
        ${GRPC_HDRS}
        CommonUtils.cpp
        CommonUtils.h
        BF/BloomFilter.h
        BF/Hash/SpookyV2.cpp
        BF/Hash/SpookyV2.h
        GGM/GGMTree.cpp
        GGM/GGMTree.h
        GGM/GGMNode.h)
target_link_libraries(SSEClient -lcrypto gRPC::grpc++ protobuf::libprotobuf)
