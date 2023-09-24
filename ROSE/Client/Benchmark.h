#ifndef BENCHMARK_H
#define BENCHMARK_H

#include <string>
#include <map>
#include <vector>
#include <utility>
#include <set>

class Benchmark
{
public:
    Benchmark() = delete;
    ~Benchmark() = default;

    explicit Benchmark(const std::string &filename, const std::string &_name="dataset",const std::string &_addr="127.0.0.1:54321");

    void benchmark_test_DataUpdate();

    void benchmark_test_Search();

    void benchmark_test_delete(const std::string &keyword_to_delete);

    void benchmark_stor();

private:
    void read_data_from_file_(const std::string &filename);

    void random_select_delected_entries(std::vector<std::pair<std::string, std::string>> &entries, int data_to_delete);

    void random_select_file_identifiers_(std::vector<std::string> &ids, std::set<int> &found_index,
                                         const std::string &keyword, int num_of_id);

    void get_client_stor();

    void get_srv_stor(int entry_num);

    void init_encrypted_database_();

    std::string global_filename;
    std::map<std::string, std::vector<std::string>> data_to_encrypt;
    std::vector<std::pair<std::string, std::string>> plane_db;
    int total_entry_num = 0;
    std::string name, addr;
};

#endif
