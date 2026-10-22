#include <iostream>
#include <string>
#include <vector>
#include <iomanip>
#include <sstream>
#include <chrono>
#include <thread>
#include <cstring>
#include <curl/curl.h>
#include <json/json.h>
#include <random>
#include <atomic>
#include <mutex>
#include <condition_variable>
#include <memory>
#include <algorithm>

// Hex and serialization helpers
static std::vector<uint8_t> hexToBytes(const std::string& hex) {
    std::vector<uint8_t> bytes;
    for (size_t i = 0; i + 1 < hex.length(); i += 2) {
        bytes.push_back(std::stoi(hex.substr(i, 2), nullptr, 16));
    }
    return bytes;
}

static std::string bytesToHex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    for (uint8_t byte : bytes) {
        ss << std::hex << std::setfill('0') << std::setw(2) << (int)byte;
    }
    return ss.str();
}

static void writeLE32(std::vector<uint8_t>& out, uint32_t value) {
    for (int i = 0; i < 4; i++) {
        out.push_back((value >> (i * 8)) & 0xFF);
    }
}

static void writeLE64(std::vector<uint8_t>& out, uint64_t value) {
    for (int i = 0; i < 8; i++) {
        out.push_back((value >> (i * 8)) & 0xFF);
    }
}

static uint32_t readBE32(const uint8_t* bytes) {
    return (uint32_t(bytes[0]) << 24) | (uint32_t(bytes[1]) << 16) |
           (uint32_t(bytes[2]) << 8) | uint32_t(bytes[3]);
}

// Bitcoin CompactSize integer
static void writeVarInt(std::vector<uint8_t>& out, uint64_t value) {
    if (value < 0xFD) {
        out.push_back(value);
    } else if (value <= 0xFFFF) {
        out.push_back(0xFD);
        out.push_back(value & 0xFF);
        out.push_back((value >> 8) & 0xFF);
    } else if (value <= 0xFFFFFFFF) {
        out.push_back(0xFE);
        writeLE32(out, value);
    } else {
        out.push_back(0xFF);
        writeLE64(out, value);
    }
}

// Lane-wise operations for the SIMD hashing below. Macros rather than helper
// functions, so the code compiles inside whichever target-specific function uses it.
#define ROTR_LANES(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define BSWAP_LANES(x) (((x) << 24) | (((x) << 8) & 0x00FF0000) | (((x) >> 8) & 0x0000FF00) | ((x) >> 24))

// SHA-256 implementation (same as before)
class SHA256 {
private:
    static const uint32_t K[64];
    static const uint32_t H0[8];
    
    static uint32_t rotr(uint32_t x, uint32_t n) {
        return (x >> n) | (x << (32 - n));
    }
    
    static uint32_t ch(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (~x & z);
    }
    
    static uint32_t maj(uint32_t x, uint32_t y, uint32_t z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }
    
    static uint32_t sig0(uint32_t x) {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }
    
    static uint32_t sig1(uint32_t x) {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }
    
    static uint32_t gamma0(uint32_t x) {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }
    
    static uint32_t gamma1(uint32_t x) {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }

public:
    static void init(uint32_t state[8]) {
        std::copy(H0, H0 + 8, state);
    }

    // SHA-256 compression function: mixes one 64-byte block, given as sixteen
    // big-endian words, into state
    static void compress(uint32_t state[8], const uint32_t block[16]) {
        uint32_t w[64];
        for (int i = 0; i < 16; i++) {
            w[i] = block[i];
        }

        // Extend the first 16 words into the remaining 48 words
        for (int i = 16; i < 64; i++) {
            w[i] = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16];
        }

        // Initialize hash value for this chunk
        uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
        uint32_t e = state[4], f = state[5], g = state[6], h_val = state[7];

        // Main loop
        for (int i = 0; i < 64; i++) {
            uint32_t temp1 = h_val + sig1(e) + ch(e, f, g) + K[i] + w[i];
            uint32_t temp2 = sig0(a) + maj(a, b, c);
            h_val = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        // Add this chunk's hash to result so far
        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h_val;
    }

    // compress() on vectors of independent messages, one per lane (GCC vector
    // extensions). Callers compile it for a SIMD instruction set by inlining it
    // into a function with a target attribute; w holds the 16 block words and
    // is used as the message schedule.
    template <typename V>
    static inline __attribute__((always_inline)) void compressLanes(V state[8], V w[64]) {
#pragma GCC unroll 48
        for (int i = 16; i < 64; i++) {
            V s0 = ROTR_LANES(w[i - 15], 7) ^ ROTR_LANES(w[i - 15], 18) ^ (w[i - 15] >> 3);
            V s1 = ROTR_LANES(w[i - 2], 17) ^ ROTR_LANES(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = s1 + w[i - 7] + s0 + w[i - 16];
        }

        V a = state[0], b = state[1], c = state[2], d = state[3];
        V e = state[4], f = state[5], g = state[6], h_val = state[7];

#pragma GCC unroll 64
        for (int i = 0; i < 64; i++) {
            V temp1 = h_val + (ROTR_LANES(e, 6) ^ ROTR_LANES(e, 11) ^ ROTR_LANES(e, 25)) + ((e & f) ^ (~e & g)) + K[i] + w[i];
            V temp2 = (ROTR_LANES(a, 2) ^ ROTR_LANES(a, 13) ^ ROTR_LANES(a, 22)) + ((a & b) ^ (a & c) ^ (b & c));
            h_val = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        state[0] += a; state[1] += b; state[2] += c; state[3] += d;
        state[4] += e; state[5] += f; state[6] += g; state[7] += h_val;
    }

    static std::string hash(const std::vector<uint8_t>& input) {
        return bytesToHex(digest(input));
    }

    // Bitcoin's double SHA-256, used for block hashes, txids and merkle nodes
    static std::vector<uint8_t> doubleDigest(const std::vector<uint8_t>& input) {
        return digest(digest(input));
    }

    static std::vector<uint8_t> digest(const std::vector<uint8_t>& input) {
        std::vector<uint8_t> message = input;
        
        // Pre-processing: adding padding bits
        message.push_back(0x80);
        
        // Pre-processing: padding with zeros
        while (message.size() % 64 != 56) {
            message.push_back(0x00);
        }
        
        // Append original length in bits mod 2^64 to message
        uint64_t bitLength = input.size() * 8;
        for (int i = 7; i >= 0; i--) {
            message.push_back((bitLength >> (i * 8)) & 0xFF);
        }
        
        // Process the message in successive 512-bit chunks
        uint32_t h[8];
        init(h);

        for (size_t chunk = 0; chunk < message.size(); chunk += 64) {
            uint32_t block[16];

            // Break chunk into sixteen 32-bit big-endian words
            for (int i = 0; i < 16; i++) {
                block[i] = (message[chunk + i * 4] << 24) |
                           (message[chunk + i * 4 + 1] << 16) |
                           (message[chunk + i * 4 + 2] << 8) |
                           (message[chunk + i * 4 + 3]);
            }

            compress(h, block);
        }
        
        // Produce the final hash value as bytes (big-endian words, per the SHA-256 spec)
        std::vector<uint8_t> result;
        for (int i = 0; i < 8; i++) {
            result.push_back((h[i] >> 24) & 0xFF);
            result.push_back((h[i] >> 16) & 0xFF);
            result.push_back((h[i] >> 8) & 0xFF);
            result.push_back(h[i] & 0xFF);
        }
        return result;
    }
};

// SHA-256 constants
const uint32_t SHA256::K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

const uint32_t SHA256::H0[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
};

// HTTP Response structure
struct HTTPResponse {
    std::string data;
    static size_t WriteCallback(void* contents, size_t size, size_t nmemb, HTTPResponse* response) {
        response->data.append((char*)contents, size * nmemb);
        return size * nmemb;
    }
};

// Bitcoin RPC Client
class BitcoinRPCClient {
private:
    std::string rpcUrl;
    std::string username;
    std::string password;
    CURL* curl;
    std::mutex curlMutex;  // A CURL easy handle must not be used by two threads at once

public:
    BitcoinRPCClient(const std::string& url, const std::string& user, const std::string& pass) 
        : rpcUrl(url), username(user), password(pass) {
        curl = curl_easy_init();
        if (!curl) {
            throw std::runtime_error("Failed to initialize CURL");
        }
    }
    
    ~BitcoinRPCClient() {
        if (curl) {
            curl_easy_cleanup(curl);
        }
    }
    
    Json::Value makeRPCCall(const std::string& method, const Json::Value& params = Json::Value(Json::arrayValue)) {
        std::lock_guard<std::mutex> lock(curlMutex);

        if (!curl) {
            throw std::runtime_error("CURL not initialized");
        }
        
        // Prepare JSON-RPC request
        Json::Value request;
        request["jsonrpc"] = "2.0";
        request["method"] = method;
        request["params"] = params;
        request["id"] = 1;
        
        Json::StreamWriterBuilder builder;
        std::string jsonString = Json::writeString(builder, request);
        
        // Setup CURL
        HTTPResponse response;
        curl_easy_setopt(curl, CURLOPT_URL, rpcUrl.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, jsonString.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, HTTPResponse::WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
        curl_easy_setopt(curl, CURLOPT_USERNAME, username.c_str());
        curl_easy_setopt(curl, CURLOPT_PASSWORD, password.c_str());
        
        // Set headers
        struct curl_slist* headers = nullptr;
        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        
        // Perform request
        CURLcode res = curl_easy_perform(curl);
        curl_slist_free_all(headers);
        
        if (res != CURLE_OK) {
            throw std::runtime_error("CURL request failed: " + std::string(curl_easy_strerror(res)));
        }
        
        // Parse response
        Json::Value jsonResponse;
        Json::CharReaderBuilder readerBuilder;
        std::string errs;
        std::istringstream stream(response.data);
        
        if (!Json::parseFromStream(readerBuilder, stream, &jsonResponse, &errs)) {
            throw std::runtime_error("Failed to parse JSON response: " + errs);
        }
        
        if (jsonResponse.isMember("error") && !jsonResponse["error"].isNull()) {
            throw std::runtime_error("RPC Error: " + jsonResponse["error"]["message"].asString());
        }
        
        return jsonResponse["result"];
    }
};

// Bitcoin Block Template
struct BlockTemplate {
    std::string previousBlockHash;
    std::vector<uint8_t> coinbaseTx;        // Serialized coinbase, with witness
    std::vector<std::string> transactions;  // Raw hex of the other transactions
    std::vector<uint8_t> merkleRoot;        // Internal byte order
    uint32_t version;
    uint32_t bits;
    uint32_t curTime;
    uint32_t height;
    std::string target;
    
    std::vector<uint8_t> getBlockHeader(uint32_t nonce) const {
        std::vector<uint8_t> header;
        
        // Version (4 bytes, little-endian)
        header.push_back(version & 0xFF);
        header.push_back((version >> 8) & 0xFF);
        header.push_back((version >> 16) & 0xFF);
        header.push_back((version >> 24) & 0xFF);
        
        // Previous block hash (32 bytes, reversed)
        for (int i = 31; i >= 0; i--) {
            std::string byteStr = previousBlockHash.substr(i * 2, 2);
            header.push_back(std::stoi(byteStr, nullptr, 16));
        }
        
        // Merkle root (32 bytes, already in internal byte order)
        header.insert(header.end(), merkleRoot.begin(), merkleRoot.end());
        
        // Timestamp (4 bytes, little-endian)
        header.push_back(curTime & 0xFF);
        header.push_back((curTime >> 8) & 0xFF);
        header.push_back((curTime >> 16) & 0xFF);
        header.push_back((curTime >> 24) & 0xFF);
        
        // Bits (4 bytes, little-endian)
        header.push_back(bits & 0xFF);
        header.push_back((bits >> 8) & 0xFF);
        header.push_back((bits >> 16) & 0xFF);
        header.push_back((bits >> 24) & 0xFF);
        
        // Nonce (4 bytes, little-endian)
        header.push_back(nonce & 0xFF);
        header.push_back((nonce >> 8) & 0xFF);
        header.push_back((nonce >> 16) & 0xFF);
        header.push_back((nonce >> 24) & 0xFF);
        
        return header;
    }
};

// Per-template data the hashing threads need. The first 64 header bytes don't
// depend on the nonce, so their SHA-256 state is computed once and each nonce
// costs two compressions instead of hashing the full header twice.
struct MiningWork {
    uint32_t midstate[8];  // SHA-256 state after header bytes 0-63
    uint32_t tail[3];      // Header bytes 64-75 (end of merkle root, time, bits)
    uint32_t target[8];    // Target as 32-bit words, most significant first
};

// SIMD version of the header hash: lane i hashes nonce firstNonce + i. Returns a
// bitmask of lanes whose hash passes on its most significant 32 bits; those are
// candidates only, to be confirmed with the full comparison in checkNonce.
template <typename V, int Lanes>
static inline __attribute__((always_inline)) uint32_t scanGroup(const MiningWork& work, uint32_t firstNonce) {
    V nonce;
    for (int i = 0; i < Lanes; i++) {
        nonce[i] = firstNonce + i;
    }

    // Second header chunk, as in checkNonce
    V w[64];
    for (int i = 0; i < 3; i++) {
        w[i] = V{} + work.tail[i];
    }
    w[3] = BSWAP_LANES(nonce);
    w[4] = V{} + 0x80000000;
    for (int i = 5; i < 15; i++) {
        w[i] = V{};
    }
    w[15] = V{} + 80 * 8;

    V state[8];
    for (int i = 0; i < 8; i++) {
        state[i] = V{} + work.midstate[i];
    }
    SHA256::compressLanes(state, w);

    // Second SHA-256 over the 32-byte first digest
    for (int i = 0; i < 8; i++) {
        w[i] = state[i];
    }
    w[8] = V{} + 0x80000000;
    for (int i = 9; i < 15; i++) {
        w[i] = V{};
    }
    w[15] = V{} + 32 * 8;

    uint32_t initial[8];
    SHA256::init(initial);
    V hash[8];
    for (int i = 0; i < 8; i++) {
        hash[i] = V{} + initial[i];
    }
    SHA256::compressLanes(hash, w);

    auto pass = BSWAP_LANES(hash[7]) <= (V{} + work.target[0]);
    uint32_t mask = 0;
    for (int i = 0; i < Lanes; i++) {
        if (pass[i]) mask |= 1u << i;
    }
    return mask;
}

#if defined(__x86_64__) || defined(__i386__)
typedef uint32_t Lanes8 __attribute__((vector_size(32)));
typedef uint32_t Lanes16 __attribute__((vector_size(64)));

__attribute__((target("avx2")))
static uint32_t scanGroupAVX2(const MiningWork& work, uint32_t firstNonce) {
    return scanGroup<Lanes8, 8>(work, firstNonce);
}

__attribute__((target("avx512f")))
static uint32_t scanGroupAVX512(const MiningWork& work, uint32_t firstNonce) {
    return scanGroup<Lanes16, 16>(work, firstNonce);
}
#endif

// Network Bitcoin Miner
class NetworkBitcoinMiner {
private:
    std::unique_ptr<BitcoinRPCClient> rpcClient;
    BlockTemplate currentTemplate;
    std::atomic<bool> mining;
    std::atomic<uint64_t> hashCount;
    std::chrono::steady_clock::time_point startTime;
    std::mutex templateMutex;
    std::vector<uint8_t> payoutScript;
    uint32_t extraNonce = 0;

    // Hashing threads poll workGeneration and reload currentWork when it changes
    MiningWork currentWork;
    std::atomic<uint64_t> workGeneration{0};
    std::condition_variable workChanged;  // Signalled under templateMutex
    std::atomic<uint64_t> solvedGeneration{0};
    std::atomic<uint64_t> blocksAccepted{0};
    unsigned threadCount;
    uint32_t (*scanGroupFn)(const MiningWork&, uint32_t);
    unsigned scanLanes;
    const char* hasherName;

    MiningWork buildWork() const {
        MiningWork work{};
        std::vector<uint8_t> header = currentTemplate.getBlockHeader(0);

        uint32_t block[16];
        for (int i = 0; i < 16; i++) {
            block[i] = readBE32(&header[i * 4]);
        }
        SHA256::init(work.midstate);
        SHA256::compress(work.midstate, block);

        for (int i = 0; i < 3; i++) {
            work.tail[i] = readBE32(&header[64 + i * 4]);
        }

        std::vector<uint8_t> target = hexToBytes(currentTemplate.target);
        if (target.size() != 32) {
            throw std::runtime_error("Unexpected target length: " + currentTemplate.target);
        }
        for (int i = 0; i < 8; i++) {
            work.target[i] = readBE32(&target[i * 4]);
        }
        return work;
    }

    // Fast path: double SHA-256 of the header with this nonce, checked against the target
    static bool checkNonce(const MiningWork& work, uint32_t nonce) {
        // Second header chunk: bytes 64-79 plus padding for an 80-byte message.
        // The nonce is stored little-endian, so as a big-endian word it is byte-swapped.
        uint32_t block[16] = {work.tail[0], work.tail[1], work.tail[2], __builtin_bswap32(nonce),
                              0x80000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 80 * 8};
        uint32_t state[8];
        std::copy(work.midstate, work.midstate + 8, state);
        SHA256::compress(state, block);

        // Second SHA-256 over the 32-byte first digest
        uint32_t block2[16] = {state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
                               0x80000000, 0, 0, 0, 0, 0, 0, 32 * 8};
        uint32_t hash[8];
        SHA256::init(hash);
        SHA256::compress(hash, block2);

        // As a number the hash is little-endian, so its most significant word is
        // the byte-swapped last word of the digest
        for (int i = 0; i < 8; i++) {
            uint32_t word = __builtin_bswap32(hash[7 - i]);
            if (word != work.target[i]) {
                return word < work.target[i];
            }
        }
        return true;
    }

    static uint32_t scanGroupScalar(const MiningWork& work, uint32_t nonce) {
        return checkNonce(work, nonce) ? 1 : 0;
    }
    
    // Pick the widest SIMD hashing this CPU supports
    void selectHasher() {
        scanGroupFn = scanGroupScalar;
        scanLanes = 1;
        hasherName = "scalar";
#if defined(__x86_64__) || defined(__i386__)
        if (__builtin_cpu_supports("avx512f")) {
            scanGroupFn = scanGroupAVX512;
            scanLanes = 16;
            hasherName = "AVX-512";
        } else if (__builtin_cpu_supports("avx2")) {
            scanGroupFn = scanGroupAVX2;
            scanLanes = 8;
            hasherName = "AVX2";
        }
#endif
    }
    
    // The nonce space is split into groups of scanLanes consecutive nonces, hashed
    // together; thread id takes groups id, id + threadCount, id + 2 * threadCount, ...
    void hashWorker(unsigned id) {
        const uint32_t batchSize = 1 << 16;
        const uint32_t step = threadCount * scanLanes;
        MiningWork work{};
        uint64_t generation = 0;
        uint32_t nonce = 0;
        bool exhausted = false;
        
        while (mining.load()) {
            if (workGeneration.load() != generation) {
                std::lock_guard<std::mutex> lock(templateMutex);
                work = currentWork;
                generation = workGeneration.load();
                nonce = id * scanLanes;
                exhausted = false;
            }
            
            // Wait for a first template, or a new one once this one is solved or
            // this thread's nonces are used up (the template thread refreshes it)
            if (generation == 0 || solvedGeneration.load() == generation || exhausted) {
                std::unique_lock<std::mutex> lock(templateMutex);
                workChanged.wait_for(lock, std::chrono::milliseconds(100),
                                     [&]() { return workGeneration.load() != generation || !mining.load(); });
                continue;
            }
            
            uint32_t done = 0;
            bool found = false;
            while (done < batchSize && !found) {
                done += scanLanes;
                uint32_t candidates = scanGroupFn(work, nonce);
                for (unsigned lane = 0; candidates != 0 && lane < scanLanes; lane++) {
                    if ((candidates >> lane & 1) && checkNonce(work, nonce + lane)) {
                        submitSolution(generation, nonce + lane);
                        found = true;
                        break;
                    }
                }
                uint32_t next = nonce + step;
                if (next < nonce) {
                    exhausted = true;
                    break;
                }
                nonce = next;
            }
            hashCount.fetch_add(done);
        }
    }
    
    void submitSolution(uint64_t generation, uint32_t nonce) {
        std::string blockHex;

        {
            std::lock_guard<std::mutex> lock(templateMutex);

            // Another thread may have solved this template already, or it was replaced
            if (workGeneration.load() != generation || solvedGeneration.load() == generation) {
                return;
            }

            // Confirm with the reference implementation before submitting
            std::vector<uint8_t> hash = SHA256::doubleDigest(currentTemplate.getBlockHeader(nonce));
            if (!isValidHash(hash)) {
                std::cerr << "Internal error: fast hash path disagrees for nonce " << nonce << std::endl;
                return;
            }
            solvedGeneration.store(generation);

            std::cout << "✓ BLOCK FOUND!" << std::endl;
            std::cout << "Hash: " << toDisplayHex(hash) << std::endl;
            std::cout << "Nonce: " << nonce << std::endl;
            std::cout << "Height: " << currentTemplate.height << std::endl;

            blockHex = createBlockHex(nonce);
        }

        // Submit and refresh outside the lock, since updateBlockTemplate takes it too
        submitBlock(blockHex);
        updateBlockTemplate();
    }

    // Block hashes are compared as 256-bit numbers, so reverse the digest into
    // display order (most significant byte first) before printing or comparing
    static std::string toDisplayHex(const std::vector<uint8_t>& hash) {
        return bytesToHex(std::vector<uint8_t>(hash.rbegin(), hash.rend()));
    }

    bool isValidHash(const std::vector<uint8_t>& hash) {
        // Equal-length lowercase hex strings compare the same way as the numbers
        return toDisplayHex(hash) <= currentTemplate.target;
    }

    // BIP34: the coinbase scriptSig must start with the block height, pushed the
    // way Bitcoin Core does it (OP_0 / OP_1..OP_16 for small heights)
    static std::vector<uint8_t> encodeHeight(uint32_t height) {
        if (height == 0) return {0x00};
        if (height <= 16) return {static_cast<uint8_t>(0x50 + height)};

        std::vector<uint8_t> num;
        for (uint32_t h = height; h > 0; h >>= 8) {
            num.push_back(h & 0xFF);
        }
        if (num.back() & 0x80) num.push_back(0x00);  // Keep the number positive

        std::vector<uint8_t> script = {static_cast<uint8_t>(num.size())};
        script.insert(script.end(), num.begin(), num.end());
        return script;
    }

    // Serialize the coinbase transaction paying the block reward to payoutScript.
    // withWitness adds the BIP141 witness reserved value that the witness
    // commitment requires; the txid is computed without it.
    std::vector<uint8_t> buildCoinbase(uint32_t height, uint64_t value,
                                       const std::vector<uint8_t>& witnessCommitment, bool withWitness) const {
        std::vector<uint8_t> tx;
        writeLE32(tx, 2);  // Version
        if (withWitness) {
            tx.push_back(0x00);  // Marker
            tx.push_back(0x01);  // Flag
        }

        // Single input spending the null outpoint
        tx.push_back(1);
        tx.insert(tx.end(), 32, 0x00);
        writeLE32(tx, 0xFFFFFFFF);

        // scriptSig: height, then an extra nonce that makes each coinbase unique
        // and keeps the script above the 2-byte consensus minimum
        std::vector<uint8_t> scriptSig = encodeHeight(height);
        scriptSig.push_back(4);
        writeLE32(scriptSig, extraNonce);
        writeVarInt(tx, scriptSig.size());
        tx.insert(tx.end(), scriptSig.begin(), scriptSig.end());
        writeLE32(tx, 0xFFFFFFFF);  // Sequence

        // Outputs: block reward, plus the witness commitment if the template has one
        writeVarInt(tx, witnessCommitment.empty() ? 1 : 2);
        writeLE64(tx, value);
        writeVarInt(tx, payoutScript.size());
        tx.insert(tx.end(), payoutScript.begin(), payoutScript.end());
        if (!witnessCommitment.empty()) {
            writeLE64(tx, 0);
            writeVarInt(tx, witnessCommitment.size());
            tx.insert(tx.end(), witnessCommitment.begin(), witnessCommitment.end());
        }

        if (withWitness) {
            tx.push_back(1);   // One witness item
            tx.push_back(32);  // 32-byte witness reserved value
            tx.insert(tx.end(), 32, 0x00);
        }

        writeLE32(tx, 0);  // Lock time
        return tx;
    }

    void updateBlockTemplate() {
        try {
            std::lock_guard<std::mutex> lock(templateMutex);

            Json::Value request;
            request["rules"].append("segwit");
            Json::Value params;
            params.append(request);

            Json::Value result = rpcClient->makeRPCCall("getblocktemplate", params);

            currentTemplate.version = result["version"].asUInt();
            currentTemplate.previousBlockHash = result["previousblockhash"].asString();
            currentTemplate.bits = std::stoul(result["bits"].asString(), nullptr, 16);
            currentTemplate.curTime = result["curtime"].asUInt();
            currentTemplate.height = result["height"].asUInt();
            currentTemplate.target = result["target"].asString();

            // Build coinbase transaction
            extraNonce++;
            std::vector<uint8_t> commitment = hexToBytes(result.get("default_witness_commitment", "").asString());
            uint64_t reward = result["coinbasevalue"].asUInt64();
            currentTemplate.coinbaseTx = buildCoinbase(currentTemplate.height, reward, commitment, !commitment.empty());

            // Calculate merkle root from txids (internal byte order, no witness data)
            std::vector<std::vector<uint8_t>> txids;
            txids.push_back(SHA256::doubleDigest(buildCoinbase(currentTemplate.height, reward, commitment, false)));

            currentTemplate.transactions.clear();
            for (const auto& tx : result["transactions"]) {
                std::vector<uint8_t> txid = hexToBytes(tx["txid"].asString());
                std::reverse(txid.begin(), txid.end());
                txids.push_back(txid);
                currentTemplate.transactions.push_back(tx["data"].asString());
            }

            currentTemplate.merkleRoot = calculateMerkleRoot(txids);
            
            currentWork = buildWork();
            workGeneration.fetch_add(1);
            workChanged.notify_all();

            std::cout << "Updated block template - Height: " << currentTemplate.height
                      << ", Transactions: " << currentTemplate.transactions.size()
                      << ", Target: " << currentTemplate.target.substr(0, 16) << "..." << std::endl;

        } catch (const std::exception& e) {
            std::cerr << "Failed to update block template: " << e.what() << std::endl;
        }
    }

    std::vector<uint8_t> calculateMerkleRoot(std::vector<std::vector<uint8_t>> hashes) {
        if (hashes.empty()) return std::vector<uint8_t>(32, 0x00);

        while (hashes.size() > 1) {
            std::vector<std::vector<uint8_t>> newLevel;
            for (size_t i = 0; i < hashes.size(); i += 2) {
                // An odd node out is paired with itself
                const std::vector<uint8_t>& right = (i + 1 < hashes.size()) ? hashes[i + 1] : hashes[i];

                std::vector<uint8_t> combined = hashes[i];
                combined.insert(combined.end(), right.begin(), right.end());
                newLevel.push_back(SHA256::doubleDigest(combined));
            }
            hashes = newLevel;
        }

        return hashes[0];
    }
    
    void submitBlock(const std::string& blockHex) {
        try {
            Json::Value params;
            params.append(blockHex);
            
            Json::Value result = rpcClient->makeRPCCall("submitblock", params);
            
            if (result.isNull()) {
                blocksAccepted.fetch_add(1);
                std::cout << "✓ BLOCK ACCEPTED BY NETWORK!" << std::endl;
                std::cout << "Congratulations! You've successfully mined a Bitcoin block!" << std::endl;
            } else {
                std::cout << "Block rejected: " << result.asString() << std::endl;
            }
        } catch (const std::exception& e) {
            std::cerr << "Failed to submit block: " << e.what() << std::endl;
        }
    }
    
public:
    NetworkBitcoinMiner(const std::string& rpcUrl, const std::string& username, const std::string& password,
                        const std::string& payoutAddress)
        : mining(false), hashCount(0) {
        rpcClient = std::make_unique<BitcoinRPCClient>(rpcUrl, username, password);

        // Test connection
        try {
            Json::Value info = rpcClient->makeRPCCall("getblockchaininfo");
            std::cout << "Connected to Bitcoin Core - Chain: " << info["chain"].asString()
                      << ", Blocks: " << info["blocks"].asUInt() << std::endl;
        } catch (const std::exception& e) {
            throw std::runtime_error("Failed to connect to Bitcoin Core: " + std::string(e.what()));
        }

        // Resolve the payout address to the script the coinbase pays
        Json::Value params;
        params.append(payoutAddress);
        Json::Value address = rpcClient->makeRPCCall("validateaddress", params);
        if (!address["isvalid"].asBool()) {
            throw std::runtime_error("Invalid payout address for this chain: " + payoutAddress);
        }
        payoutScript = hexToBytes(address["scriptPubKey"].asString());

        threadCount = std::max(1u, std::thread::hardware_concurrency());
        selectHasher();
    }
    
    void startMining() {
        if (mining.load()) {
            std::cout << "Already mining!" << std::endl;
            return;
        }
        
        mining.store(true);
        hashCount.store(0);
        startTime = std::chrono::steady_clock::now();
        
        std::cout << "Starting Bitcoin mining on " << threadCount << " threads, "
                  << hasherName << " hashing (" << scanLanes << " nonces at a time)..." << std::endl;
        
        // Template update thread; each refresh also bumps the extra nonce,
        // giving the hashing threads a fresh nonce space
        std::thread templateThread([this]() {
            while (mining.load()) {
                updateBlockTemplate();
                std::this_thread::sleep_for(std::chrono::seconds(30));
            }
        });
        
        // Stats thread
        std::thread statsThread([this]() {
            while (mining.load()) {
                std::this_thread::sleep_for(std::chrono::seconds(10));
                printStats();
            }
        });
        
        // Hashing threads
        std::vector<std::thread> workers;
        for (unsigned i = 0; i < threadCount; i++) {
            workers.emplace_back(&NetworkBitcoinMiner::hashWorker, this, i);
        }
        
        templateThread.join();
        statsThread.join();
        for (auto& worker : workers) {
            worker.join();
        }
    }
    
    void stopMining() {
        mining.store(false);
        std::cout << "Stopping mining..." << std::endl;
    }
    
    void printStats() {
        auto currentTime = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(currentTime - startTime);
        
        if (duration.count() > 0) {
            double hashRate = hashCount.load() / static_cast<double>(duration.count());
            std::cout << "Hash Rate: " << std::fixed << std::setprecision(2) << hashRate / 1e6 << " MH/s"
                      << " | Total Hashes: " << hashCount.load()
                      << " | Blocks Accepted: " << blocksAccepted.load() << std::endl;
        }
    }
    
private:
    std::string createBlockHex(uint32_t nonce) {
        // Header, transaction count, coinbase, then the template's transactions
        std::vector<uint8_t> block = currentTemplate.getBlockHeader(nonce);
        writeVarInt(block, 1 + currentTemplate.transactions.size());
        block.insert(block.end(), currentTemplate.coinbaseTx.begin(), currentTemplate.coinbaseTx.end());

        std::string blockHex = bytesToHex(block);
        for (const auto& tx : currentTemplate.transactions) {
            blockHex += tx;
        }
        return blockHex;
    }
};

int main() {
    std::cout << "Network Bitcoin Miner v1.0" << std::endl;
    std::cout << "===========================" << std::endl;
    
    // Bitcoin Core connection settings
    std::string rpcUrl, username, password;
    
    std::cout << "Enter Bitcoin Core RPC URL (e.g., http://localhost:8332): ";
    std::getline(std::cin, rpcUrl);
    
    std::cout << "Enter RPC username: ";
    std::getline(std::cin, username);
    
    std::cout << "Enter RPC password: ";
    std::getline(std::cin, password);

    std::string payoutAddress;
    std::cout << "Enter payout address for block rewards: ";
    std::getline(std::cin, payoutAddress);

    try {
        // Initialize CURL
        curl_global_init(CURL_GLOBAL_DEFAULT);

        NetworkBitcoinMiner miner(rpcUrl, username, password, payoutAddress);
        
        std::cout << "\nStarting network mining..." << std::endl;
        std::cout << "Press Ctrl+C to stop." << std::endl;
        
        miner.startMining();
        
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    curl_global_cleanup();
    return 0;
}
