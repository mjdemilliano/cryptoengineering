#include <iostream>
#include <iomanip>
#include <fstream>

#include <mbedtls/aes.h>

#define KEY_SIZE_BYTES 32
#define DATA_SIZE  16

void print(const unsigned char *data, size_t len)
{
    for (int i = 0; i < len; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int) data[i] << " ";
    }
    std::cout << std::endl;
}

int main(int argc, char *argv[])
{
    unsigned char data[DATA_SIZE];

    std::ifstream ifs;

    if (argc != 2) {
        std::cerr << "usage: " << argv[0] << " <plaintext file>" << std::endl;
        return 1;
    }

    ifs.open(argv[1], std::ifstream::in);
    ifs.read(reinterpret_cast<char *>(data), DATA_SIZE);
    
    mbedtls_aes_context ctx;
    mbedtls_aes_init(&ctx);

    unsigned char output[DATA_SIZE];
    int result = 0;

    const unsigned char key[KEY_SIZE_BYTES] =
            {0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

    result = mbedtls_aes_setkey_enc(&ctx, key, 8 * KEY_SIZE_BYTES);
    if (result) {
        std::cerr << "error setting key" << std::endl;
        goto exit;        
    }
    
    mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, data, output);
    
    print(output, DATA_SIZE);
    
exit:
    mbedtls_aes_free(&ctx);
    return result;
}