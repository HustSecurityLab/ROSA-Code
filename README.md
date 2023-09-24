# Source Code Running Explanations

This repository contains the source code of manuscript entitled "Let It Go Correctly: On the Robustness of Dynamic Searchable Encryption with Non-Interactive Search."

## 1. Software Environments

### 1.1. Overview

| System                  | Dependent Library    |
|:-----------------------:|:--------------------:|
| Ubuntu Server-22.04 x64 | OpenSSL, Relic, gRPC |

### 1.2. Command to Install Necessary Softwares and Libraries

#### 1.2.1. Install Compiler

`sudo apt-get install -y git cmake gcc g++`

#### 1.2.2. Install [Relic Library](https://github.com/relic-toolkit/relic)

```shell
git clone https://github.com/relic-toolkit/relic
cd relic
mkdir build
cmake ../ -DMULTI=PTHREAD -DFP_PRIME=256
cmake --build . --parallel
sudo cmake --install .
```

#### 1.2.3. Install Dependencies

`sudo apt-get install -y libssl-dev libgrpc++-dev libgrpc-dev libprotobuf-c-dev libprotoc-dev protobuf-c-compiler protobuf-compiler-grpc libgmp-dev`

### 1.3. (**IMPORTANT!**) Potential Problems with gRPC and protobuf Library

The source code relies on the gRPC and protobuf libraries that are found by the provided .cmake scripts. However, some environments, such as Anaconda Python Development Environment, have their own gRPC and protobuf libraries that are different from those found by CMake and expose them to the environment variables, which will cause compilation errors. Hence, if having errors about conflicted gRPC and probobuf libraries, please remove those paths from the shell environment variables before compiling the source code.

## 2. Run Code

### 2.1. Dataset

We provide a python script **generate_data.py** to generate the test dataset in the online manner. Please run it to generate the test dataset file **sse-data-large**. Of course one can modify it to generate different dataset.

### 2.2. Execution

To run the experiments, please firstly enter the directory whose name is the scheme. Then compile the code as below

```shell
mkdir build
cd build
cmake ../
cmake --build . --parallel
```

Next, copy the dataset file **sse-data-large** into the just-created *build* directory.

Then, launch the server by running:

`./SSEServer`

Finally, launch the client by running

`./SSEClient`
