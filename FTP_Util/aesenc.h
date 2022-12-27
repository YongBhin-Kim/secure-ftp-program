#pragma once
#ifndef __AESENC_H__
#define __AESENC_H__
void handleErrors(void);
int aes_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext);
int aes_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext);

int gcm_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *add, int add_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, unsigned char *tag);
int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *add, int add_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext, unsigned char *tag);


#endif