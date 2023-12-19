#include <iostream>
#include <cstdint>
#include <random>
#include <fstream>
#include <vector>
#include <stdexcept>
#include <limits>
#include <cstring> 

using namespace std;

class FeistelNetworkCipher {
private:
    static const int NumRounds = 8;
    uint64_t primarySecretKey;
    vector<uint64_t> subkeys;

    uint64_t createMainKey() {
        random_device rd;
        mt19937_64 gen(rd());
        uniform_int_distribution<uint64_t> dis(0, numeric_limits<uint64_t>::max());
        return dis(gen);
    }

    void generateSubkeys() {
        for (int i = 0; i < NumRounds; ++i) {
            subkeys.push_back(rotateRight(primarySecretKey, i * 3));
        }
    }

    uint32_t roundFunction(uint32_t leftPart, uint64_t subkey) {
        uint32_t rotatedLeft = rotateLeft(leftPart, 9);
        uint32_t rotatedRightKey = rotateRight(static_cast<uint32_t>(subkey), 11);
        return rotatedLeft ^ (~rotatedRightKey ^ leftPart);
    }

    uint64_t rotateLeft(uint64_t value, int numBits) {
        return (value << numBits) | (value >> (64 - numBits));
    }

    uint64_t rotateRight(uint64_t value, int numBits) {
        return (value >> numBits) | (value << (64 - numBits));
    }

public:
    FeistelNetworkCipher() {
        primarySecretKey = createMainKey();
        generateSubkeys();
    }

    void processEncryption(uint64_t& blockData) {
        uint32_t left = static_cast<uint32_t>(blockData >> 32);
        uint32_t right = static_cast<uint32_t>(blockData);

        for (int round = 0; round < NumRounds; ++round) {
            uint32_t temp = right ^ roundFunction(left, subkeys[round]);
            if (round < NumRounds - 1) {
                right = left;
                left = temp;
            }
            else {
                right = temp;
            }
        }

        blockData = (static_cast<uint64_t>(left) << 32) | right;
    }

    void processDecryption(uint64_t& blockData) {
        uint32_t left = static_cast<uint32_t>(blockData >> 32);
        uint32_t right = static_cast<uint32_t>(blockData);

        for (int round = NumRounds - 1; round >= 0; --round) {
            uint32_t temp = right ^ roundFunction(left, subkeys[round]);
            if (round > 0) {
                right = left;
                left = temp;
            }
            else {
                right = temp;
            }
        }

        blockData = (static_cast<uint64_t>(left) << 32) | right;
    }

    void padBlock(vector<char>& block) {
        size_t paddingSize = 8 - block.size();
        for (size_t i = 0; i < paddingSize; i++) {
            block.push_back(static_cast<char>(paddingSize));
        }
    }

    void unpadBlock(vector<char>& block) {
        char paddingSize = block.back();
        block.erase(block.end() - paddingSize, block.end());
    }
};

int main() {
    ifstream inputFile("input.txt");
    ofstream encryptedFile("encrypted.txt", ios::binary);

    if (!inputFile.is_open() || !encryptedFile.is_open()) {
        throw runtime_error("Error opening files");
    }

    FeistelNetworkCipher cipher;
    vector<char> block;
    block.reserve(8);
    size_t bytesRead;
    bool lastBlock = false;

    while (!lastBlock) {
        block.clear();
        char ch;
        while (block.size() < 8 && inputFile.get(ch)) {
            block.push_back(ch);
        }
        bytesRead = block.size();
        lastBlock = bytesRead < 8;
        if (lastBlock) {
            cipher.padBlock(block);
        }
        uint64_t blockData = 0;
        memcpy(&blockData, block.data(), block.size());
        cipher.processEncryption(blockData);
        encryptedFile.write(reinterpret_cast<char*>(&blockData), 8);
    }

    inputFile.close();
    encryptedFile.close();

    ifstream encryptedInputFile("encrypted.txt", ios::binary);
    ofstream decryptedOutputFile("decrypted.txt");

    if (!encryptedInputFile.is_open() || !decryptedOutputFile.is_open()) {
        throw runtime_error("Error opening files");
    }

    uint64_t blockData; 
    while (encryptedInputFile.read(reinterpret_cast<char*>(&blockData), sizeof(blockData))) {
        cipher.processDecryption(blockData);
        block.assign(8, 0);
        memcpy(block.data(), &blockData, 8);
        if (encryptedInputFile.peek() == EOF) {
            cipher.unpadBlock(block);
        }
        decryptedOutputFile.write(block.data(), block.size());
    }

    encryptedInputFile.close();
    decryptedOutputFile.close();

    return 0;
}
