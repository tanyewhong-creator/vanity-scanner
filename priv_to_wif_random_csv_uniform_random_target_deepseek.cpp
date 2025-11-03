#include <iostream>
#include <string>
#include <random>
#include <atomic>
#include <mutex>
#include <thread>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <omp.h>
#include <openssl/sha.h>
#include <openssl/ripemd.h>
#include <algorithm>
#include <fstream>
#include <unordered_set>
#include <cctype>
#include <vector>
#include <secp256k1.h>
#include <io.h>
#include <immintrin.h> // For AVX instructions
#include <array>
#include <string_view>
#include <set>
#include <nlohmann/json.hpp>
using json = nlohmann::json;
using namespace std;
const string FIXED_PREFIX_HEX = "";
unsigned char PREFIX_BYTES[32] = {0};
atomic<bool> stop_flag(false);
// Fast hex conversion lookup tables
const char hex_chars[] = "0123456789abcdef";
unsigned char hex_to_val[256];
char byte_to_hex[256][3];
void init_lookup_tables() {
    for (int i = 0; i < 256; i++) {
        hex_to_val[i] = 0;
        snprintf(byte_to_hex[i], 3, "%02x", i);
    }
    for (int i = 0; i < 16; i++) {
        hex_to_val[(unsigned char)hex_chars[i]] = i;
        hex_to_val[(unsigned char)toupper(hex_chars[i])] = i;
    }
}
void signal_handler(int sig) {
    stop_flag = true;
}
// Optimized base58 encoding with lookup tables
string encode_base58(const unsigned char* data, size_t len) {
    static const char* alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    static vector<int> mapping(256, -1);
    static bool mapping_initialized = false;
   
    if (!mapping_initialized) {
        for (int i = 0; i < 58; i++) {
            mapping[(unsigned char)alphabet[i]] = i;
        }
        mapping_initialized = true;
    }
   
    string result;
    size_t zeros = 0;
    while (zeros < len && data[zeros] == 0) ++zeros;
    size_t input_size = len - zeros;
    if (input_size == 0) return string(zeros, '1');
   
    size_t output_size = input_size * 138 / 100 + 1;
    vector<unsigned char> output(output_size, 0);
   
    for (size_t i = zeros; i < len; ++i) {
        uint32_t carry = data[i];
        for (size_t j = output_size; j-- > 0;) {
            carry += static_cast<uint32_t>(output[j]) << 8;
            output[j] = carry % 58;
            carry /= 58;
        }
    }
   
    size_t start = 0;
    while (start < output_size && output[start] == 0) ++start;
    result.reserve(zeros + output_size - start);
    result.assign(zeros, '1');
    for (size_t i = start; i < output_size; ++i) {
        result += alphabet[output[i]];
    }
    return result;
}
// Fast SHA256 implementation using OpenSSL's optimized version
void fast_sha256(const unsigned char* input, size_t len, unsigned char* output) {
    SHA256(input, len, output);
}
// Fast RIPEMD160 implementation
void fast_ripemd160(const unsigned char* input, size_t len, unsigned char* output) {
    RIPEMD160(input, len, output);
}
// Batch processing structure
struct KeyBatch {
    array<unsigned char, 32> priv_key;
    string address;
    string wif;
    string priv_hex;
    string pub_hex;
};
int main() {
    init_lookup_tables();
   
    size_t prefix_hex_len = FIXED_PREFIX_HEX.length();
    if (prefix_hex_len % 2 != 0) {
        cerr << "Fixed prefix hex length must be even." << endl;
        return 1;
    }
    size_t prefix_bytes_len = prefix_hex_len / 2;
    if (prefix_bytes_len > 32) {
        cerr << "Fixed prefix too long." << endl;
        return 1;
    }
   
    // Convert FIXED_PREFIX_HEX to bytes using lookup table
    for (size_t i = 0; i < prefix_hex_len; i += 2) {
        unsigned char h1 = FIXED_PREFIX_HEX[i];
        unsigned char h2 = FIXED_PREFIX_HEX[i + 1];
        PREFIX_BYTES[i / 2] = (hex_to_val[h1] << 4) | hex_to_val[h2];
    }
    signal(SIGINT, signal_handler);
    ios::sync_with_stdio(false);
   
    const long long MAX_FILE_SIZE = 1LL * 1024 * 1024 * 1024;
    int file_num = 1;
    string filename = "bitcoin_keys_1.csv";
   
    // Check existing files to continue from last
    while (true) {
        ifstream test(filename);
        if (!test.good()) break;
        file_num++;
        filename = "bitcoin_keys_" + to_string(file_num) + ".csv";
    }
    file_num = max(1, file_num - 1);
    filename = "bitcoin_keys_" + to_string(file_num) + ".csv";
   
    FILE* out = fopen(filename.c_str(), "a");
    if (!out) {
        cerr << "Cannot open file: " << filename << endl;
        return 1;
    }
   
    long long current_size = ftell(out);
    if (current_size == 0) {
        fprintf(out, "priv_hex,pub_hex,address,wif\n");
        current_size = ftell(out);
    }
   
    // Load target prefixes using nlohmann/json into owned strings
    vector<string> owned_prefixes;
    owned_prefixes.reserve(20000000);
    ifstream prefix_file("target_prefixes.jsonl");
    if (prefix_file.is_open()) {
        string line;
        while (getline(prefix_file, line)) {
            if (line.empty()) continue;
            try {
                json j = json::parse(line);
                owned_prefixes.push_back(j.get<string>());
            } catch (...) {
                // Ignore invalid lines
            }
        }
    }
    prefix_file.close();
   
    // Compute max_prefix_len
    size_t max_prefix_len = 0;
    for (const auto& p : owned_prefixes) {
        max_prefix_len = std::max(max_prefix_len, p.length());
    }
   
    // Create prefix sets by length
    vector<unordered_set<string_view>> prefix_sets(max_prefix_len + 1);
    set<size_t> used_lengths;
    for (const auto& prefix : owned_prefixes) {
        size_t len = prefix.length();
        prefix_sets[len].insert(prefix);
        used_lengths.insert(len);
    }
   
    atomic<long long> tried(0);
    atomic<long long> stored(0);
    mutex file_mutex;
   
    int num_threads = omp_get_num_procs();
    omp_set_num_threads(num_threads);
   
    // Batch processing to reduce lock contention
    const int BATCH_SIZE = 1000;
   
    thread status_thread([&]() {
        auto start = chrono::steady_clock::now();
        long long last_tried = 0;
        while (!stop_flag) {
            this_thread::sleep_for(chrono::seconds(2));
            long long curr_tried = tried.load();
            long long curr_stored = stored.load();
            double rate = static_cast<double>(curr_tried - last_tried) / 2.0;
            last_tried = curr_tried;
            auto now = chrono::steady_clock::now();
            auto hours = chrono::duration_cast<chrono::seconds>(now - start).count();
            printf("\rTried: %lld (%.2fM/s), Stored: %lld, Rate: %.2f keys/sec, Time: %02lld:%02lld:%02lld",
                   curr_tried, curr_tried / 1000000.0, curr_stored, rate,
                   hours / 3600, (hours % 3600) / 60, hours % 60);
            fflush(stdout);
        }
        printf("\nStopped by user.\n");
    });
#pragma omp parallel
    {
        // Thread-local resources
        random_device rd;
        mt19937_64 gen(rd() + omp_get_thread_num());
        uniform_int_distribution<uint64_t> dist64(0, UINT64_MAX);
       
        secp256k1_context* secp_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
       
        // Pre-allocated buffers to avoid reallocation
        unsigned char priv_bytes[32];
        unsigned char pub_buf[65];
        unsigned char sha_buf[SHA256_DIGEST_LENGTH];
        unsigned char ripe_buf[RIPEMD160_DIGEST_LENGTH];
        unsigned char versioned[21];
        unsigned char hash1[SHA256_DIGEST_LENGTH];
        unsigned char hash2[SHA256_DIGEST_LENGTH];
        unsigned char addr_bin[25];
        unsigned char wif_payload[33];
        unsigned char wif_bin[37];
       
        vector<KeyBatch> batch;
        batch.reserve(BATCH_SIZE);
       
        int full_u64 = (32 - prefix_bytes_len) / 8;
        int rem_bytes = (32 - prefix_bytes_len) % 8;
       
        while (!stop_flag) {
            batch.clear();
           
            for (int b = 0; b < BATCH_SIZE && !stop_flag; b++) {
                // Fast private key generation using 64-bit chunks
                memcpy(priv_bytes, PREFIX_BYTES, prefix_bytes_len);
               
                // Generate remaining bytes using 64-bit operations
                uint64_t* priv_ptr = reinterpret_cast<uint64_t*>(priv_bytes + prefix_bytes_len);
                for (int i = 0; i < full_u64; ++i) {
                    priv_ptr[i] = dist64(gen);
                }
                for (int i = 0; i < rem_bytes; ++i) {
                    priv_bytes[prefix_bytes_len + full_u64 * 8 + i] = static_cast<unsigned char>(dist64(gen));
                }
               
                if (!secp256k1_ec_seckey_verify(secp_ctx, priv_bytes)) {
                    tried.fetch_add(1, memory_order_relaxed);
                    continue;
                }
               
                // Generate public key
                secp256k1_pubkey pubkey;
                if (!secp256k1_ec_pubkey_create(secp_ctx, &pubkey, priv_bytes)) {
                    tried.fetch_add(1, memory_order_relaxed);
                    continue;
                }
               
                size_t pub_len = 65;
                secp256k1_ec_pubkey_serialize(secp_ctx, pub_buf, &pub_len, &pubkey, SECP256K1_EC_UNCOMPRESSED);
               
                // Generate address
                fast_sha256(pub_buf, 65, sha_buf);
                fast_ripemd160(sha_buf, SHA256_DIGEST_LENGTH, ripe_buf);
               
                versioned[0] = 0x00;
                memcpy(versioned + 1, ripe_buf, 20);
               
                fast_sha256(versioned, 21, hash1);
                fast_sha256(hash1, SHA256_DIGEST_LENGTH, hash2);
               
                memcpy(addr_bin, versioned, 21);
                memcpy(addr_bin + 21, hash2, 4);
               
                string address = encode_base58(addr_bin, 25);
               
                // Check prefix match using hash sets
                bool matches = false;
                for (auto len : used_lengths) {
                    if (address.length() < len) continue;
                    string_view sub(address.c_str(), len);
                    if (prefix_sets[len].count(sub)) {
                        matches = true;
                        break;
                    }
                }
               
                if (!matches) {
                    tried.fetch_add(1, memory_order_relaxed);
                    continue;
                }
               
                // Generate WIF
                wif_payload[0] = 0x80;
                memcpy(wif_payload + 1, priv_bytes, 32);
               
                fast_sha256(wif_payload, 33, hash1);
                fast_sha256(hash1, SHA256_DIGEST_LENGTH, hash2);
               
                memcpy(wif_bin, wif_payload, 33);
                memcpy(wif_bin + 33, hash2, 4);
               
                string wif = encode_base58(wif_bin, 37);
               
                // Fast hex conversion using lookup table
                string priv_hex;
                priv_hex.reserve(64);
                for (int i = 0; i < 32; i++) {
                    priv_hex.append(byte_to_hex[priv_bytes[i]]);
                }
               
                string pub_hex;
                pub_hex.reserve(130);
                for (int i = 0; i < 65; i++) {
                    pub_hex.append(byte_to_hex[pub_buf[i]]);
                }
               
                batch.push_back({});
                auto& key = batch.back();
                memcpy(key.priv_key.data(), priv_bytes, 32);
                key.address = move(address);
                key.wif = move(wif);
                key.priv_hex = move(priv_hex);
                key.pub_hex = move(pub_hex);
               
                tried.fetch_add(1, memory_order_relaxed);
            }
           
            // Batch write to file
            if (!batch.empty()) {
                lock_guard<mutex> lock(file_mutex);
               
                for (const auto& key : batch) {
                    if (current_size >= MAX_FILE_SIZE) {
                        fclose(out);
                        file_num++;
                        filename = "bitcoin_keys_" + to_string(file_num) + ".csv";
                        out = fopen(filename.c_str(), "w");
                        if (out) {
                            fprintf(out, "priv_hex,pub_hex,address,wif\n");
                            current_size = ftell(out);
                        } else {
                            cerr << "Cannot open file: " << filename << endl;
                            stop_flag = true;
                            break;
                        }
                    }
                   
                    fprintf(out, "%s,%s,%s,%s\n",
                           key.priv_hex.c_str(), key.pub_hex.c_str(),
                           key.address.c_str(), key.wif.c_str());
                    current_size = ftell(out);
                    stored.fetch_add(1, memory_order_relaxed);
                }
                fflush(out);
                _commit(_fileno(out));
            }
        }
       
        secp256k1_context_destroy(secp_ctx);
    }
   
    status_thread.join();
    if (out) fclose(out);
    return 0;
}
// g++ priv_to_wif_random_csv_uniform_random_target_deepseek.cpp -o priv_to_wif_random_csv_uniform_random_target_deepseek.exe -fopenmp -lsecp256k1 -lssl -lcrypto -lpthread -std=c++17 -Wno-deprecated-declarations -O3 -march=native -flto=auto -fomit-frame-pointer -funroll-loops -DNDEBUG
