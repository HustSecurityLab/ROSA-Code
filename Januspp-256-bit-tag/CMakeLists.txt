cmake_minimum_required(VERSION 3.0.0)
project(Januspp-256 VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 17)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/protobuf)

find_package(Protobuf REQUIRED)
find_package(GRPC REQUIRED)

set(PROTOS
        ${CMAKE_CURRENT_SOURCE_DIR}/protobuf/januspp.proto)

set(PROTO_SRC_DIR ${CMAKE_CURRENT_BINARY_DIR}/protobuf)
file(MAKE_DIRECTORY ${PROTO_SRC_DIR})
include_directories(${PROTO_SRC_DIR} ${GRPC_INCLUDE_DIR} ${PROTOBUF_INCLUDE_DIR})

protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_SRC_DIR} ${PROTOS})
grpc_generate_cpp(GRPC_SRCS GRPC_HDRS ${PROTO_SRC_DIR} ${PROTOS})

add_executable(SSEClient
                CommonUtils.cpp
                CommonUtils.h
                Client/DianaClient.cpp
                Client/DianaClient.h
                Client/JanusppClient.cpp
                Client/JanusppClient.h
                Client/SSEClient.cpp
                Client/SSEClient.h
                Client/RunSSEClient.cpp
                Client/Benchmark.cpp
                Client/Benchmark.h
                constrained_prf.cpp
                constrained_prf.h
                pun_encryption.cpp
                pun_encryption.h
                pun_prf.cpp
                pun_prf.h
                ${PROTO_SRCS}
                ${PROTO_HDRS}
                ${GRPC_SRCS}
                ${GRPC_HDRS})
target_link_libraries(SSEClient -lcrypto gRPC::grpc++ protobuf::libprotobuf)

add_executable(SSEServer
                CommonUtils.cpp
                CommonUtils.h
                Server/DianaServer.cpp
                Server/DianaServer.h
                Server/JanusppServer.cpp
                Server/JanusppServer.h
                Server/SSEServer.cpp
                Server/SSEServer.h
                Server/RunSSEServer.cpp
                constrained_prf.cpp
                constrained_prf.h
                pun_encryption.cpp
                pun_encryption.h
                pun_prf.cpp
                pun_prf.h
                ${PROTO_SRCS}
                ${PROTO_HDRS}
                ${GRPC_SRCS}
                ${GRPC_HDRS})
target_link_libraries(SSEServer -lcrypto gRPC::grpc++ protobuf::libprotobuf)
