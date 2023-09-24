cmake_minimum_required(VERSION 3.10.0)
project(Aura VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 17)

if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
#When using MinGW64 Compiler
link_libraries(absl_log_internal_message absl_log_internal_check_op absl_cord absl_cord_internal absl_cordz_info gpr absl_synchronization)
endif()

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/protobuf)

find_package(Protobuf REQUIRED)
find_package(GRPC REQUIRED)

set(PROTOS
        ${CMAKE_CURRENT_SOURCE_DIR}/protobuf/aura.proto)

set(PROTO_SRC_DIR ${CMAKE_CURRENT_BINARY_DIR}/protobuf)
file(MAKE_DIRECTORY ${PROTO_SRC_DIR})
include_directories(${PROTO_SRC_DIR} ${GRPC_INCLUDE_DIR} ${PROTOBUF_INCLUDE_DIR})

protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_SRC_DIR} ${PROTOS})
grpc_generate_cpp(GRPC_SRCS GRPC_HDRS ${PROTO_SRC_DIR} ${PROTOS})

add_executable(SSEClient
                Client/AuraClient.cpp
                Client/AuraClient.h
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
                GGM/GGMNode.h
                Client/SSEClient.cpp
                Client/SSEClient.h
                Client/Benchmark.cpp
                Client/Benchmark.h
                Client/RunSSEClient.cpp)
target_link_libraries(SSEClient -lcrypto gRPC::grpc++ protobuf::libprotobuf)

add_executable(SSEServer
                Server/AuraServer.cpp
                Server/AuraServer.h
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
                GGM/GGMNode.h
                Server/SSEServer.cpp
                Server/SSEServer.h
                Server/RunSSEServer.cpp)

target_link_libraries(SSEServer -lcrypto gRPC::grpc++ protobuf::libprotobuf)