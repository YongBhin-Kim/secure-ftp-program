/*
    Secure FTP Project (c Yongbhin Kim)
        - FTP application program
        - Client
*/



#include <openssl/aes.h>
#include <openssl/bio.h>
#include <assert.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include "../FTP_Util/msg.h"
#include "../FTP_Util/aesenc.h"
#include "../FTP_Util/readnwrite.h"
#include "../FTP_Util/secure_communication.h"
#define  MODE 2


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <fcntl.h> // open,


// params.h
#define BUF_SIZE            256

// userDB return values
#define USER_ALREADY_EXTSTS 32//302
#define USER_NOT_FOUND      44//404
#define SIGNUP_SUCCESS      23//200
#define SIGN_FAIL           24//201

#define NOT_CORRECT         9
#define CORRECT_ID          10
#define CORRECT_PW          11

// command
#define COMMAND_LIST        100
#define COMMAND_DOWN        110
#define FILE_NOT_FOUND      111
#define COMMAND_UP          120


int sign(int sock);
void handle_command(int sock);

void send_up_file(int sock, char* src_file);
void recv_down_file(int sock, char *filename2);

void msg_split(char* msg, char* command, char* filename1, char* filename2);
int size(char* msg);

void error_handling(char *msg);


char plaintext[BUFSIZE+AES_BLOCK_SIZE] = {0X00, };
unsigned char key[AES_KEY_128] = {0x00, };
unsigned char iv[AES_IV_128] = {0x00, };
unsigned char additional[ADDSIZE] = {0x00, };


int main(int argc, char* argv[]) {

    int sock, ret;
    struct sockaddr_in serv_addr;

    /* ================================= */
    /* variable for secure communication */
    int cnt_i, len;
    BIO *rpub = NULL;
    RSA *rsa_pubkey = NULL;

    int n;
    int plaintext_len;
    int ciphertext_len;
    /* ================================= */


    if (argc != 3) {
        printf("Usage : %s <IP> <Port> \n", argv[0]);
        exit(1);
    }
    
    // socket
    sock = socket(PF_INET, SOCK_STREAM, 0);
    if ( sock == -1 )
        error_handling("socket() error ");
    
    // serv addr setting
    memset(&serv_addr, 0, sizeof(serv_addr) );
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(argv[1]);
    serv_addr.sin_port = htons(atoi(argv[2]));


    /* ================================= */
    /*         aes-gcm setting           */
    RAND_poll(); 
    RAND_bytes(key, sizeof(key));

    for (cnt_i=0; cnt_i<AES_KEY_128; cnt_i++)
        iv[cnt_i] = (unsigned char) cnt_i;
    for (cnt_i=0; cnt_i<ADDSIZE; cnt_i++)
        additional[cnt_i] = (unsigned char) cnt_i;
    /* ================================= */


    
    // connect
    if ( connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1 )
        error_handling("connect() error");
    
    // setup process
    rsaes_setup_process(sock, key, rsa_pubkey, NULL, CLIENT_SIDE); // receive rsa pubkey and send aes session key

    // client process
    ret = sign(sock);
    handle_command(sock);

    printf("\nclient를 종료합니다.\n");
    

    close(sock);
    return 0;

}


int sign(int sock) {

    printf("\n ======================\n");
    printf(" |     Login Page     |\n");
    printf(" ----------------------\n");
    printf(" sign up \n");
    printf(" sign in \n");
    printf(" q or Q \n");
    printf(" ======================\n");
    printf(" > ");

    char msg[BUFSIZE];
    memset(&msg, 0, BUFSIZE);
    fgets(msg, BUFSIZE, stdin);

    if ( !strcmp(msg, "q\n") || !strcmp(msg, "Q\n") ) {
        close(sock);
        exit(0);
    }

    char status[BUFSIZE] = {0, };
    char id[BUFSIZE];
    char pw[BUFSIZE];
    int ret = SIGN_FAIL;


    while(1) {
        printf("[To server] %s\n", msg);
        
        send_message(sock, msg, additional, key, iv); // send 'sign up' or 'sign in' message

        if ( !strcmp(msg, "sign up\n") || !strcmp(msg, "sign up") ) {

            printf(" new id > ");
            fgets(id, BUFSIZE, stdin);
            id[size(id)] = '\0';
            send_message(sock, id, additional, key, iv);

            printf(" new pw > ");
            fgets(pw, BUFSIZE, stdin);
            pw[size(pw)] = '\0';
            send_message(sock, pw, additional, key, iv);

            // status 받기 : 성공 OR 이미 존재하는 유저
            recv_message(sock, status, additional, key, iv, CLIENT_SIDE);


            // 회원가입 성공(USER_NOT_FOUND) --> 로그인
            if ( status[0] == USER_NOT_FOUND ) {
                printf("Success to sign up \n");
            }
            // Already exists OR After sign up
            else if ( status[0] == USER_ALREADY_EXTSTS ) { 
                printf("Already exists ID \n");
            }
            char now_msg[BUFSIZE] = "sign in\n";
            ret = sign(sock);
            break;
        }
        else if ( !strcmp(msg, "sign in\n") || !strcmp(msg, "sign in") ) {

            printf(" id > ");
            fgets(id, BUFSIZE, stdin);
            id[size(id)] = '\0';
            send_message(sock, id, additional, key, iv);

            printf(" pw > ");
            fgets(pw, BUFSIZE, stdin);
            pw[size(pw)] = '\0';
            send_message(sock, pw, additional, key, iv);

            // decrypted_readn(sock, status, sizeof(status));
            recv_message(sock, status, additional, key, iv, CLIENT_SIDE);
            if ( status[0] == (CORRECT_ID + CORRECT_PW) ) {
                printf(" ----------------------\n");
                printf("  *  Login success  *  \n");
                printf(" ======================\n");
                ret = SIGNUP_SUCCESS;
                break;
                return ret;
                
            }
            else if ( status[0] == CORRECT_ID ) {
                printf("Check your Password\n ");
            }
            else if ( status[0] == NOT_CORRECT )
                printf("Check your ID \n");
            else {
                printf("sign in 에러\n");
            }
        }
        else {
            error_handling("Error msg");
        }
    }

    return ret;
}

void handle_command(int sock) {

    while (1) {

        printf("\n\n ======================\n");
        printf(" |       Command      |\n");
        printf(" ----------------------\n");
        printf(" list \n");
        printf(" up \n");
        printf(" down \n");
        printf(" q or Q \n");
        printf(" ======================\n");
        printf(" > ");    

        char msg[BUFSIZE];
        memset(&msg, 0, BUFSIZE);
        fgets(msg, BUFSIZE, stdin);

        if ( !strcmp(msg, "q\n") || !strcmp(msg, "Q\n") ) {
            close(sock);
            exit(0);
        }

        send_message(sock, msg, additional, key, iv); // send 'sign up' or 'sign in' message


        memset(&plaintext, 0, sizeof(plaintext));
        recv_message(sock, plaintext, additional, key, iv, CLIENT_SIDE); // list OR up OR down

        char command[BUF_SIZE], filename1[BUF_SIZE], filename2[BUF_SIZE];
        msg_split(msg, command, filename1, filename2);

        if ( !strcmp(command, "list") || !strcmp(command, "list\n") || !strcmp(command, "list\n ") || !strcmp(command, "list ") ) {
            while ( strcmp(plaintext, "eof") )
                recv_message(sock, plaintext, additional, key, iv, CLIENT_LIST);
        }
        else if ( !strcmp(command, "up ") || !strcmp(command, "up") || !strcmp(command, "up\n") ) {
            send_up_file(sock, filename1);
        }
        else if ( !strcmp(command, "down ") || !strcmp(command, "down") || !strcmp(command, "down\n") ) {
            recv_down_file(sock, filename2);
        }
        else {
            error_handling("Error commmand ");
        }

    }

}

// aes-gcm
void recv_down_file(int sock, char *filename2) {

    memset(&plaintext, 0, sizeof(plaintext));
    recv_message(sock, plaintext, additional, key, iv, CLIENT_SIDE); // 파일 내용 , CLIENT_SIDE받기

    char tmp[BUFSIZE];
    int fd = open(filename2, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    sprintf( tmp, "%s", plaintext);
    // tmp[strlen(tmp)-1] = '\0';
    write(fd, tmp, strlen(tmp)); // 파일에 쓰기

    close(fd);
}

// aes-gcm
void send_up_file(int sock, char* src_file) {
    // file open and send status
    FILE* ptr = fopen(src_file, "rb");

    if (ptr == NULL) {
        printf("File open error\n");
        return;
    }

    while (!feof(ptr)) {
        fgets(plaintext, BUFSIZE, ptr);
        send_message(sock, plaintext, additional, key, iv);
        memset(&plaintext, 0, sizeof(plaintext));
    }
}

int size(char* msg) {
    if (msg == NULL)
        return 0;

    int i = 0;
    while(1) {
        if (msg[i++] == '\n')
            return i-1;
    }

}

void msg_split(char* msg, char* command, char* filename1, char* filename2) {

    if ( !strcmp(msg, "list\n") || !strcmp(msg, "list") ) {
        strcpy(command, msg);
        return;
    }

	char *ptr = strtok(msg, " ");

    if (ptr != NULL)
	{
        strcpy(command, ptr);
		ptr = strtok(NULL, " ");
        if (ptr != NULL) {
            strcpy(filename1, ptr);
            ptr = strtok(NULL, " ");
            strcpy(filename2, ptr);
        }
	}
}

// EOF