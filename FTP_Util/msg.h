

#ifndef __MSG_H__
#define __MSG_H__

#define BUFSIZE         512
#define AES_BLOCK_SIZE  16
#define AES_KEY_128     16
#define AES_IV_128      12
#define TAGSIZE         16
#define ADDSIZE         32

enum MSG_TYPE {
    PUBLIC_KEY,
    SECRET_KEY,
    PUBLIC_KEY_REQUEST,
    IV,
    ENCRYPTED_KEY,
    ENCRYPTED_MSG,
};

typedef struct _APP_MSG {
    int type;
    unsigned char payload[BUFSIZE + AES_BLOCK_SIZE]; // 이상
    int msg_len;
} APP_MSG;




#endif