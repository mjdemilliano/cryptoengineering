#include <iostream>
#include <iomanip>
#include <fstream>
#include <iterator>

#include <mbedtls/aes.h>

#define KEY_SIZE_BYTES  32
#define BLOCK_SIZE_BYTES    16
#define IV_SIZE_BYTES   16

void print(const unsigned char *data, size_t len)
{
    for (int i = 0; i < len; ++i) {
        if (i % 16 == 0) {
            std::cout << std::endl;
        }    
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) data[i] << " ";
    }
    std::cout << std::dec << std::endl;
}

void print(const std::string& data)
{
    print(reinterpret_cast<const unsigned char *>(data.data()), data.size());
}

std::string read_file(const char *filename)
{
    std::string output;
    std::ifstream ifs;
    ifs.open(filename, std::ifstream::in);
    char block[BLOCK_SIZE_BYTES];
    while (ifs.good()) {
        ifs.read(block, BLOCK_SIZE_BYTES);
        output.append(block, ifs.gcount());
    }
    return output;
}

const unsigned char * ciphertext_block(const std::string& ciphertext, int block)
{
    return reinterpret_cast<const unsigned char *>(ciphertext.data() + block * BLOCK_SIZE_BYTES);
}

void block_xor(const unsigned char *a, const unsigned char *b, unsigned char *output)
{
    assert(BLOCK_SIZE_BYTES % 8 == 0);
    // Do XOR 64-bits at the time. This is premature optimization but allows me to write an impressive line of code.
    for (int i = 0; i < BLOCK_SIZE_BYTES / 8; ++i) {
        *((uint64_t *) &output[i * 8]) = *((uint64_t *) &a[i * 8]) ^ *((uint64_t *) &b[i * 8]);
    }    
}

int main(int argc, char *argv[])
{
    if (argc != 3) {
        std::cerr << "usage: " << argv[0] << " <ciphertext file> <key file>" << std::endl;
        return 1;
    }

    std::string ciphertext(read_file(argv[1]));
    std::string key(read_file(argv[2]));

    std::cout << "ciphertext file (" << ciphertext.size() << " bytes): ";
    print(ciphertext);
    std::cout << std::endl;
    
    // Ciphertext file starts with IV. Extract it in a separate variable.
    std::string iv = ciphertext.substr(0, IV_SIZE_BYTES);
    ciphertext.erase(0, IV_SIZE_BYTES);

    std::cout << "iv (" << iv.size() << " bytes): ";
    print(iv);
    std::cout << std::endl;
    std::cout << "ciphertext (" << ciphertext.size() << " bytes): ";
    print(ciphertext);
    std::cout << std::endl;

    if (ciphertext.size() % BLOCK_SIZE_BYTES != 0) {
        std::cerr << "error decrypting, ciphertext is " << ciphertext.size() << " bytes long, but it must be a multiple of the block size (" << BLOCK_SIZE_BYTES << "  bytes)" << std::endl;
        return 1;
    }

    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    /*
     * CBC mode:
     *
     *     C_i = E(K, P_i XOR C_i-1)
     *     C_0 = IV
     *
     * Decrypting:
     *
     *     P_i XOR C_i-1 = D(K, C_i)  =>  P_i = D(K, C_i) XOR C_i-1
     */

    std::string plaintext;
    int result = 0;

    result = mbedtls_aes_setkey_dec(&ctx, reinterpret_cast<const unsigned char *>(key.data()), 8 * KEY_SIZE_BYTES);
    if (result) {
        std::cerr << "error setting key" << std::endl;
        mbedtls_aes_free(&ctx);
        return 1;       
    }

    const int num_blocks = ciphertext.size() / BLOCK_SIZE_BYTES;
    unsigned char output1[BLOCK_SIZE_BYTES];
    unsigned char output2[BLOCK_SIZE_BYTES];
    for (int block = 0; block < num_blocks; ++block) {
        result = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, ciphertext_block(ciphertext, block), output1);
        if (result) {
            std::cerr << "error decrypting block" << std::endl;
            break;
        }
        // Plaintext is decrypted block XOR'ed with the previous ciphertext block, or the IV in case this is the first block.
        block_xor(output1, block == 0 ? reinterpret_cast<const unsigned char *>(iv.data()) : ciphertext_block(ciphertext, block-1), output2);
        plaintext.append(reinterpret_cast<const char *>(output2), BLOCK_SIZE_BYTES);
    }    
    
    std::cout << "plaintext as hex: ";
    print(plaintext);
    std::cout << "plaintext as string: " << std::endl;
    std::cout << plaintext << std::endl;
    
    mbedtls_aes_free(&ctx);
    return result;
}