#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/pem.h>

void handle_errors() {
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
}

int main() {
    // Initialize OpenSSL error strings
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

    // 1. Generate ECDSA Key Pair
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!pctx || EVP_PKEY_keygen_init(pctx) <= 0 || EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) <= 0) {
        handle_errors();
    }
    if (EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        handle_errors();
    }
    printf("ECDSA Key Pair generated successfully.\n");

    // 2. Message to Sign
    const char *message = "This is a test message for ECDSA!";
    size_t message_len = strlen(message);
    printf("Message: %s\n", message);

    // 3. Sign the Message
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    size_t sig_len = 0;
    unsigned char *signature = NULL;

    if (!mdctx || EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        handle_errors();
    }
    // Determine the buffer size for the signature
    if (EVP_DigestSign(mdctx, NULL, &sig_len, (unsigned char *)message, message_len) <= 0) {
        handle_errors();
    }
    signature = OPENSSL_malloc(sig_len);
    if (!signature) {
        handle_errors();
    }
    // Generate the signature
    if (EVP_DigestSign(mdctx, signature, &sig_len, (unsigned char *)message, message_len) <= 0) {
        handle_errors();
    }
    printf("Message signed successfully.\n");

    // 4. Verify the Signature
    if (EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, pkey) <= 0) {
        handle_errors();
    }
    if (EVP_DigestVerify(mdctx, signature, sig_len, (unsigned char *)message, message_len) == 1) {
        printf("Signature verification: SUCCESS!\n");
    } else {
        printf("Signature verification: FAILED!\n");
    }

    // 5. Clean up
    EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    OPENSSL_free(signature);
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
