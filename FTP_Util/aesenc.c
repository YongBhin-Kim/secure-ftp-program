#include "aesenc.h"
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <assert.h>
#include <openssl/conf.h>
#include <openssl/sha.h>

int aes_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if ( !(ctx = EVP_CIPHER_CTX_new()) )
        handleErrors();
    if ( 1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) )
        handleErrors();
    if ( 1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) )
        handleErrors();
    ciphertext_len = len;

    if ( 1 != EVP_EncryptFinal_ex(ctx, ciphertext+len, &len) )
        handleErrors();
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int aes_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if ( !(ctx = EVP_CIPHER_CTX_new()) )
        handleErrors();

    if ( 1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv) )
        handleErrors();

    if ( 1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) )
        handleErrors();
    plaintext_len = len;
    
    printf("1\n");
    // 수정 코드
    // int ret = EVP_DecryptFinal_ex(ctx, plaintext+len, &len);
    // if ( ret != 1 ) {
    //     printf("ret = %d\n", ret);
    //     handleErrors();
    // }

    // 원래 코드
    if ( 1 != EVP_DecryptFinal_ex(ctx, plaintext+len, &len) ) {
        handleErrors();
    }
    
    plaintext_len += len;

    printf("len=%d\n", len);
    for (int i=0; i<len; i++)
        printf("[%02x] ", plaintext[i]);

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;

}

int gcm_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *add, int add_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned char *tag) {
    EVP_CIPHER_CTX *ctx = NULL;
    int len;
    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    // 암호화
    if( 1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv) ) // 키스케줄링
        handleErrors();

    if( 1 != EVP_EncryptUpdate(ctx, NULL, &len, add, add_len) ) // 암호문
        handleErrors();

    if( 1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len) ) // 암호문
        handleErrors();

    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) // 마지막 블록
        handleErrors();
    ciphertext_len += len;

    if ( 1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) )
        handleErrors();

    if( ctx != NULL )
        EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;

}

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *add, int add_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext, unsigned char *tag) {

    EVP_CIPHER_CTX *ctx = NULL;
    int len;
    int plaintext_len;
    int ret;

    // 구조체 변수에 대한 공간 할당
    if ( !(ctx = EVP_CIPHER_CTX_new()) )
        handleErrors();

    // 복호화
    if ( 1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, key, iv) ) // 키스케줄링
        handleErrors();

    if ( 1 != EVP_DecryptUpdate(ctx, NULL, &len, add, add_len) ) // 복호문
        handleErrors();

    if ( 1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) ) // 복호문
        handleErrors();
    plaintext_len = len;

    if ( !EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag) )
        handleErrors();

    ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    if ( ctx != NULL)
        EVP_CIPHER_CTX_free(ctx);


    if ( ret > 0) {
        // Success
        plaintext_len += len;
        return plaintext_len;
    }
    else {
        //failed
        return -1;
    }
}

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}
