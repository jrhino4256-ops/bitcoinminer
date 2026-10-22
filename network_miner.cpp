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
        std::vector<uint32_t> h = {H0[0], H0[1], H0[2], H0[3], H0[4], H0[5], H0[6], H0[7]};
        
        for (size_t chunk = 0; chunk < message.size(); chunk += 64) {
            uint32_t w[64];
            
            // Break chunk into sixteen 32-bit big-endian words
            for (int i = 0; i < 16; i++) {
                w[i] = (message[chunk + i * 4] << 24) |
                       (message[chunk + i * 4 + 1] << 16) |
                       (message[chunk + i * 4 + 2] << 8) |
                       (message[chunk + i * 4 + 3]);
            }
            
            // Extend the first 16 words into the remaining 48 words
            for (int i = 16; i < 64; i++) {
                w[i] = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16];
            }
            
            // Initialize hash value for this chunk
            uint32_t a = h[0], b = h[1], c = h[2], d = h[3];
            uint32_t e = h[4], f = h[5], g = h[6], h_val = h[7];
            
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
            h[0] += a; h[1] += b; h[2] += c; h[3] += d;
            h[4] += e; h[5] += f; h[6] += g; h[7] += h_val;
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
    }
    
    void startMining() {
        if (mining.load()) {
            std::cout << "Already mining!" << std::endl;
            return;
        }
        
        mining.store(true);
        hashCount.store(0);
        startTime = std::chrono::steady_clock::now();
        
        std::cout << "Starting Bitcoin mining..." << std::endl;
        
        // Template update thread
        std::thread templateThread([this]() {
            while (mining.load()) {
                updateBlockTemplate();
                std::this_thread::sleep_for(std::chrono::seconds(30));
            }
        });
        
        // Mining thread
        std::thread miningThread([this]() {
            uint32_t nonce = 0;
            
            while (mining.load()) {
                bool haveTemplate = false;
                std::string blockHex;

                {
                    std::lock_guard<std::mutex> lock(templateMutex);

                    if (!currentTemplate.target.empty()) {
                        haveTemplate = true;

                        // Double SHA-256 of the block header
                        std::vector<uint8_t> hash = SHA256::doubleDigest(currentTemplate.getBlockHeader(nonce));
                        hashCount.fetch_add(1);

                        if (isValidHash(hash)) {
                            std::cout << "✓ BLOCK FOUND!" << std::endl;
                            std::cout << "Hash: " << toDisplayHex(hash) << std::endl;
                            std::cout << "Nonce: " << nonce << std::endl;
                            std::cout << "Height: " << currentTemplate.height << std::endl;

                            blockHex = createBlockHex(nonce);
                        }
                    }
                }

                if (!haveTemplate) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    continue;
                }

                // Submit and refresh outside the lock, since updateBlockTemplate takes it too
                if (!blockHex.empty()) {
                    submitBlock(blockHex);
                    updateBlockTemplate();
                    nonce = 0;
                } else {
                    nonce++;
                    if (nonce % 1000000 == 0) {
                        printStats();
                    }
                    // Nonce space exhausted: a fresh template gets a new extra nonce
                    if (nonce == 0) {
                        updateBlockTemplate();
                    }
                }
            }
        });
        
        templateThread.join();
        miningThread.join();
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
            std::cout << "Hash Rate: " << std::fixed << std::setprecision(2) << hashRate << " H/s"
                      << " | Total Hashes: " << hashCount.load() << std::endl;
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
