cmake_minimum_required(VERSION 3.0.0)
project(Mitra VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 17)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/protobuf)

find_package(Protobuf REQUIRED)
find_package(GRPC REQUIRED)

set(PROTOS
        ${CMAKE_CURRENT_SOURCE_DIR}/protobuf/mitra.proto)

set(PROTO_SRC_DIR ${CMAKE_CURRENT_BINARY_DIR}/protobuf)
file(MAKE_DIRECTORY ${PROTO_SRC_DIR})
include_directories(${PROTO_SRC_DIR} ${GRPC_INCLUDE_DIR} ${PROTOBUF_INCLUDE_DIR})

protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_SRC_DIR} ${PROTOS})
grpc_generate_cpp(GRPC_SRCS GRPC_HDRS ${PROTO_SRC_DIR} ${PROTOS})

add_executable(SSEClient
                Client/MitraClient.cpp
                Client/MitraClient.h
                Client/SSEClient.cpp
                Client/SSEClient.h
                ${PROTO_SRCS}
                ${PROTO_HDRS}
                ${GRPC_SRCS}
                ${GRPC_HDRS}
                Client/RunSSEClient.cpp
                CommonUtils.cpp
                CommonUtils.h
                Client/Benchmark.cpp
                Client/Benchmark.h)
target_link_libraries(SSEClient -lcrypto gRPC::grpc++ protobuf::libprotobuf)

add_executable(SSEServer
                Server/MitraServer.cpp
                Server/MitraServer.h
                ${PROTO_SRCS}
                ${PROTO_HDRS}
                ${GRPC_SRCS}
                ${GRPC_HDRS}
                Server/SSEServer.cpp
                Server/SSEServer.h
                Server/RunSSEServer.cpp
                CommonUtils.cpp
                CommonUtils.h)
target_link_libraries(SSEServer -lcrypto gRPC::grpc++ protobuf::libprotobuf)