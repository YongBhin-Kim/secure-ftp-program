#ifndef __SECURE_COMMUNICATION__
#define __SECURE_COMMUNICATION__

#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

#include "msg.h"
#include "aesenc.h"
#include "readnwrite.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <assert.h>

#define SERVER_SIDE 10000
#define CLIENT_SIDE 20000
#define CLIENT_LIST 20001

#define MODE

// SIDE :
//     - SERVER : send rsa pubkey and receive aes session key
//     - CLIENT : receive rsa pubkey and send aes session key
int rsaes_setup_process(int sock, unsigned char *key, BIO *rsa_pubkey, BIO *rsa_privkey, int side);

// send aes-gcm encrypted message
void send_message(int sock, char *plaintext, unsigned char *additional, unsigned char *key, unsigned char *iv);
void recv_message(int sock, char *plaintext, unsigned char *additional, unsigned char *key, unsigned char *iv, int type);

// print ciphertext or plaintext 
void print(unsigned char *msg, int size);

// error handling
void error_handling(char *msg);

#endif