
#include "secure_communication.h"

APP_MSG msg_in, msg_out;

int rsaes_setup_process(int sock, unsigned char *key, BIO *rsa_pubkey, BIO *rsa_privkey, int side) {


    // setup process - server side
    if ( side == SERVER_SIDE )
    {
        int n;
        int publickey_len;
        int encryptedkey_len;
        BIO *pub = NULL;
        unsigned char buffer[BUFSIZE] = { 0x00, };

        memset(&msg_in, 0, sizeof(APP_MSG)); // msg_out

        n = readn(sock, &msg_in, sizeof(APP_MSG)); // 공개키 요청 메시지 수신
        msg_in.type = ntohl(msg_in.type);
        msg_in.msg_len = ntohl(msg_in.msg_len);
        if ( n == -1 )
            error_handling("readn() error");
        else if ( n == 0 )
            error_handling("reading EOF");
        
        if ( msg_in.type != PUBLIC_KEY_REQUEST )
            error_handling("message error (PUBLIC_KEY_REQUEST)");
        else {
            // sending PUBLIC_KEY
            memset(&msg_out, 0, sizeof(msg_out));
            msg_out.type = PUBLIC_KEY;
            msg_out.type = htonl(msg_out.type);

            pub = BIO_new(BIO_s_mem());
            PEM_write_bio_RSAPublicKey(pub, rsa_pubkey);
            publickey_len = BIO_pending(pub);

            BIO_read(pub, msg_out.payload, publickey_len);
            msg_out.msg_len = htonl(publickey_len);
            
            n = writen(sock, &msg_out, sizeof(APP_MSG)); // clnt_sock
            if ( n == -1 )
                error_handling("writen() error");
        }

        // 클라이언트로부터 암호화된 세션키 수신, 복호화하여 세션키 복원
        memset(&msg_in, 0, sizeof(APP_MSG)); // msg_out
        n = readn(sock, &msg_in, sizeof(APP_MSG));

        msg_in.type = ntohl(msg_in.type);
        msg_in.msg_len = ntohl(msg_in.msg_len);

        if ( msg_in.type != ENCRYPTED_KEY ) {
            error_handling("message error (ENCRYPTED_KEY)");
        }
        else {
            encryptedkey_len = RSA_private_decrypt(msg_in.msg_len, msg_in.payload, buffer, rsa_privkey, RSA_PKCS1_OAEP_PADDING);
            memcpy(key, buffer, encryptedkey_len);
#if SECURE_UI
            printf("SK : "); print(key, 16); // yb
#endif

        }
    }

    // setup process - client side
    else if ( side == CLIENT_SIDE )
    {
        int n;
        BIO *rpub = NULL;

        // sending PUBLIC_RSA_KEY_REQUEST msg (공개키 요청)
        memset(&msg_out, 0, sizeof(msg_out));
        msg_out.type = PUBLIC_KEY_REQUEST;
        msg_out.type = htonl(msg_out.type);

        n = writen(sock, &msg_out, sizeof(APP_MSG)); //serv_sock
        if (n == -1)
            error_handling("writen() error!");
        
        // receving PUBLIC_KEY msg (공개키 수신)
        memset(&msg_in, 0, sizeof(APP_MSG)); // msg_out
        n = readn(sock, &msg_in, sizeof(APP_MSG));
        msg_in.type = ntohl(msg_in.type);
        msg_in.msg_len = ntohl(msg_in.msg_len);

        if (n == -1)
            error_handling("readn() error");
        else if (n == 0) 
            error_handling("reading EOF");
        
        if (msg_in.type != PUBLIC_KEY) 
            error_handling("message error");
        else {
            // 공개키 출력
            // BIO_dump_fp(stdout, (const char*)msg_in.payload, msg_in.msg_len);
            rpub = BIO_new_mem_buf(msg_in.payload, -1);
            BIO_write(rpub, msg_in.payload, msg_in.msg_len); // rpub로 공개키 읽어들이기
            if ( !PEM_read_bio_RSAPublicKey(rpub, &rsa_pubkey, NULL, NULL) )
                error_handling("PEM_read_bio_RSAPublicKey() error");

        }

        // sending ENCRYPTED_KEY msg (공개키로 암호화된 비밀키 송신)
        memset(&msg_out, 0, sizeof(APP_MSG));
        msg_out.type = ENCRYPTED_KEY;
        msg_out.type = htonl(msg_out.type);
        msg_out.msg_len = RSA_public_encrypt(AES_KEY_128, key, msg_out.payload, rsa_pubkey, RSA_PKCS1_OAEP_PADDING);
        msg_out.msg_len = htonl(msg_out.msg_len);
#if SECURE_UI
        // print session key
        printf("SK : "); print(key, AES_KEY_128); 
#endif

        n = writen(sock, &msg_out, sizeof(APP_MSG));
        if (n == -1)
            error_handling("writen() error!");
    }
    else {
        error_handling("check if side isn't `SERVER` or `CLIENT` ");
    }
}

void send_message(int sock, char *plaintext, unsigned char *additional, unsigned char *key, unsigned char *iv) {

    int len, plaintext_len, ciphertext_len, n;
    unsigned char tag[TAGSIZE] = { 0x00, };
    

    // removing '\n'
    len = strlen(plaintext);
    if ( plaintext[len-1] == '\n' )
        plaintext[len-1] = '\0';
    if ( strlen(plaintext) == 0 )
        return;

    memset(&msg_out, 0, sizeof(msg_out));
    msg_out.type = ENCRYPTED_MSG;
    msg_out.type = htonl(msg_out.type);
    ciphertext_len = gcm_encrypt((unsigned char*)plaintext, len, additional, strlen((char*)additional), key, iv, msg_out.payload, tag);
    msg_out.msg_len = htonl(ciphertext_len);


    // sending the inputed message
    n = writen(sock, &msg_out, sizeof(APP_MSG));
    if ( n == -1 ) {
        error_handling("wrtien() error");
        return;
    }
    n = writen(sock, tag, 16);
    if(n == -1){
        error_handling("writen() error");
        return;
    }

}

void recv_message(int sock, char *plaintext, unsigned char *additional, unsigned char *key, unsigned char *iv, int type) {

    int n, plaintext_len;
    unsigned char tag[TAGSIZE] = { 0x00, };

    // receving a message from server
    n = readn(sock, &msg_in, sizeof(APP_MSG));
    if ( n == -1 ) {
        error_handling("wrtien() error");
        return;
    }
    if ( n == 0 )
        return;

    n = readn(sock, tag, 16);
    if ( n == -1 ) {
        error_handling("wrtien() error");
        return;
    }
    if ( n == 0 )
        return;

    msg_in.type = ntohl(msg_in.type);
    msg_in.msg_len = ntohl(msg_in.msg_len);
    switch(msg_in.type) {
        case ENCRYPTED_MSG:
            // encrypted message
#if SECURE_UI
            printf("\n* encryptedMsg: \n");
            BIO_dump_fp(stdout, (const char *)msg_in.payload, msg_in.msg_len);
#endif

            // decrypted message
            plaintext_len = gcm_decrypt(msg_in.payload, msg_in.msg_len, additional, strlen((char*)additional), key, iv, (unsigned char*)plaintext, tag);
#if SECURE_UI
            printf("* decryptedMsg: \n");
            plaintext[plaintext_len] = '\0';
            printf("%s\n", plaintext);
#endif

            if ( type == CLIENT_LIST ) {
                plaintext[plaintext_len] = '\0';
                if ( strcmp(plaintext, "eof") )
                    printf("%s ", plaintext);
            }
            break;
        default:
            break;
    }

}

// print ciphertext or plaintext
void print(unsigned char *msg, int size) {
    for (int i=0; i<size; i++) {
        printf("%02x ", msg[i]);
        if ( (i % 16) == 15 )
            printf("\n");
    }
}

void error_handling(char *msg) {
	fputs(msg, stderr);
	fputc('\n', stderr);
	exit(1);
}