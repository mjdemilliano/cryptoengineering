#include <iostream>

#include <mbedtls/des.h>

#define INPUT_SIZE  8
#define KEY_SIZE 8  // 56-bit key information but highest bit of each byte is parity.

unsigned char key[KEY_SIZE] = {'z', 'e', 'k', 'e', 'y', '@', '#', '9'};
const unsigned char input[INPUT_SIZE] = {'t', 'e', 's', 't', '@', '9', 'P', '-'};

int encrypt(const unsigned char *input, const unsigned char *key, unsigned char *output)
{
    int result;

    mbedtls_des_context ctx;
    mbedtls_des_init(&ctx);

    result = mbedtls_des_setkey_enc(&ctx, key);
    if (0 == result) {
        result = mbedtls_des_crypt_ecb(&ctx, input, output);    
    }    
    mbedtls_des_free(&ctx);

    return result;
}

void invert(const unsigned char *input, unsigned char *output, size_t len)
{
    for (int i = 0; i < len; ++i) {
        output[i] = ~input[i];
    }
}

void print_output(const unsigned char *data, size_t len)
{
    for (int i = 0; i < len; ++i) {
        std::cout << std::hex << (int) data[i] << " ";
    }
    std::cout << std::endl;
}

bool compare(const unsigned char *x1, const unsigned char *x2, size_t len)
{
    bool is_equal = true;
    for (int i = 0; is_equal && i < len; ++i) {
        is_equal = is_equal && x1[i] == x2[i];
    }
    return is_equal;
}

int main(int argc, char *argv[])
{
    unsigned char input_inverted[INPUT_SIZE];
    unsigned char key_inverted[KEY_SIZE];
    
    unsigned char output1[INPUT_SIZE];
    unsigned char output2[INPUT_SIZE];
    unsigned char output2_inverted[INPUT_SIZE];
    int result;

    mbedtls_des_key_set_parity(key);    // Assign parity bits.

    invert(input, input_inverted, INPUT_SIZE);
    invert(key, key_inverted, KEY_SIZE);

    mbedtls_des_key_set_parity(key_inverted);    // Assign parity bits.

    result = encrypt(input, key, output1);
    if (result) {
        std::cerr << "error encrypting (try #1)" << std::endl;
        return 2;
    }

    result = encrypt(input_inverted, key_inverted, output2);
    if (result) {
        std::cerr << "error encrypting (try #2)" << std::endl;
        return 2;
    }

    invert(output2, output2_inverted, INPUT_SIZE);

    std::cout << "output1: ";
    print_output(output1, INPUT_SIZE);
    std::cout << "output2: ";
    print_output(output2, INPUT_SIZE);
    std::cout << "output2 inverted: ";
    print_output(output2_inverted, INPUT_SIZE);

    bool is_equal = compare(output1, output2_inverted, INPUT_SIZE);
    std::cout << "output1 == output2 inverted? " << (is_equal ? "yes" : "no") << std::endl;

    return is_equal ? 0 : 1;
}