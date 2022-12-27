/*
    Secure FTP Project (c Yongbhin Kim)
        - FTP application program
        - Server
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
#define MODE 1

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>

#include <dirent.h> // list command

#include <fcntl.h> // up command :  open()

// params.h
#define BUF_SIZE            256
#define MAX_FILE_SIZE       1000
#define MAX_CLNT            256
#define MAX_ID_SIZE         20
#define MAX_PW_SIZE         20

// userDB return values
#define USER_ALREADY_EXTSTS 32//302
#define USER_NOT_FOUND      44//404
#define SIGNUP_SUCCESS      23//200
#define SIGN_FAIL           24//201

#define NOT_CORRECT         9
#define CORRECT_ID          10
#define CORRECT_PW          11

// manage userDB type
#define INSERT_USER         55//550
#define EXISTS_CHECK        56//551
#define CERT_CHECK          57//552

// command
#define COMMAND_LIST        100
#define COMMAND_DOWN        110
#define FILE_NOT_FOUND      111
#define COMMAND_UP          120
#define SUCCESS             1
#define FAIL                -1

// handle client sign
void *handle_clnt(void *arg);                             /* handle client - sign & command */

void handle_sign(int clnt_sock);                              /* handle client - sign           */
int manage_userDB(int sock, char* id, char* pw, int TYPE);  /* handle user database           */

// handle client command
int handle_command(int clnt_sock);                          /* handle client - command        */
void send_encrypted_list_msg(int clnt_sock);                /* list            command        */
void recv_up_file(int clnt_sock, char *dst_file_name);      /* up              command        */
void send_down_file(int clnt_sock, char* file_name1);       /* down            command        */

// treating message
int msg_split(char* msg, char* command, char* filename1, char* filename2);

// treating error case
void error_handling(char *msg);

// mutex
pthread_mutex_t mutx;

char plaintext[BUFSIZE+AES_BLOCK_SIZE];
unsigned char key[AES_KEY_128];
unsigned char iv[AES_IV_128];
unsigned char additional[ADDSIZE];

int clnt_socks[MAX_CLNT];
int clnt_cnt;


int main(int argc, char* argv[]) {

    // socket
    int serv_sock;
    int clnt_sock;
    struct sockaddr_in serv_addr;
    struct sockaddr_in clnt_addr;
    socklen_t clnt_addr_size;

    // thread
    pthread_t handle_clnt_thread;

    // argument error
    if (argc != 2) {
        printf("Usage : %s <Port> \n", argv[0]);
        exit(1);
    }

    pthread_mutex_init(&mutx, NULL); // mutex init

    /* ================================= */
    /* variable for secure communication */
    int cnt_i;
    APP_MSG msg_in, msg_out;
    // char plaintext[BUFSIZE+AES_BLOCK_SIZE] = { 0x00, };
    int n;
    int len;
    int plaintext_len;
    int ciphertext_len;
    int publickey_len;
    int encryptedkey_len;
    BIO *bp_public = NULL;
    BIO *bp_private = NULL;
    BIO *pub = NULL;
    BIO *rsa_pubkey = NULL;
    BIO *rsa_privkey = NULL;
    for (cnt_i=0; cnt_i<AES_KEY_128; cnt_i++) 
        iv[cnt_i] = (unsigned char)cnt_i;
    for (cnt_i=0; cnt_i<ADDSIZE; cnt_i++)
        additional[cnt_i] = (unsigned char) cnt_i;
    /* ================================= */

    // Create server socket
    serv_sock = socket(PF_INET, SOCK_STREAM, 0);
    if ( serv_sock == -1 )
        error_handling("socket() error ");

    // server socket setting
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_addr.sin_port = htons(atoi(argv[1]));

    // binding
    if ( bind(serv_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) == -1 )
        error_handling("bind() error!");

    // listen
    if ( listen(serv_sock, 5) == -1 ) 
        error_handling("listen() error!");

    // reading public key
    bp_public = BIO_new_file("FTP_Secure/public.pem", "r");
    if ( !PEM_read_bio_RSAPublicKey(bp_public, &rsa_pubkey, NULL, NULL) )
        goto err;

    // reading private key
    bp_private = BIO_new_file("FTP_Secure/private.pem", "r");
    if ( !PEM_read_bio_RSAPrivateKey(bp_private, &rsa_privkey, NULL, NULL) )
        goto err;


    while(1)
    {   
        // Accept client socket
        clnt_addr_size = sizeof(clnt_addr);
        clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_addr, &clnt_addr_size);

        printf("\n[Client connected] IP: %s Port : %d\n", inet_ntoa(clnt_addr.sin_addr), clnt_addr.sin_port);

        pthread_mutex_lock(&mutx); // 뮤텍스 lock
        clnt_socks[clnt_cnt++]=clnt_sock; // 클라이언트 수와 파일 디스크립터를 등록
        pthread_mutex_unlock(&mutx); // 뮤텍스 unlock

        // setup process
        rsaes_setup_process(clnt_sock, key, rsa_pubkey, rsa_privkey, SERVER_SIDE); // send rsa pubkey and receive aes session key

        // Client membership registration OR certification checking (sign up or sign in)
        pthread_create(&handle_clnt_thread, NULL, handle_clnt, (void*)&clnt_sock);
        int ret = pthread_detach(&handle_clnt_thread); 

    }

    printf("서버를 종료합니다.\n");
    pthread_mutex_destroy(&mutx);
err:
    close(serv_sock);
    return 0;
}

void *handle_clnt(void *arg) {
    int clnt_sock = *((int*) arg);
    int ret;

    handle_sign(clnt_sock);

    while ( (ret = handle_command(clnt_sock)) == SUCCESS )
        continue;

    printf("Quit... \n");
    --clnt_cnt; // 클라이언트 수 감소
    close(clnt_sock); // 클라이언트와의 송수신을 위한 생성했던 소켓종료
    return NULL;

}

void handle_sign(int clnt_sock) {
    
    char id[BUFSIZE];
    char pw[BUFSIZE];
    char status[BUFSIZE] = { 0, };

    printf("[Server] for socket %d\n", clnt_sock);
    int ret;

    char msg[BUFSIZE];

    // pthread_mutex_lock(&mutx);
    while(1) {
        memset(&msg, 0, sizeof(msg));
        recv_message(clnt_sock, msg, additional, key, iv, SERVER_SIDE);
        printf("\n[(sign) Client request] : %s\n", msg);

        // 회원가입
        if ( !strcmp(msg, "sign up\n") || !strcmp(msg, "sign up") || !strcmp(msg, "sign up ") ) { 
            char new_id[BUFSIZE];
            char new_pw[BUFSIZE];

            // 1. read new id
            recv_message(clnt_sock, new_id, additional, key, iv, SERVER_SIDE);
            printf("new_id : %s\n", new_id);

            // 1. read new pw
            recv_message(clnt_sock, new_pw, additional, key, iv, SERVER_SIDE);
            printf("new_pw : %s\n", new_pw);

            ret = manage_userDB(clnt_sock, new_id, new_pw, EXISTS_CHECK);

            if ( ret == USER_NOT_FOUND ) { // new client 등록
                status[0] = (char)ret;
                send_message(clnt_sock, status, additional, key, iv);
                
                ret = manage_userDB(clnt_sock, new_id, new_pw, INSERT_USER);
                printf("[Sign up] New User ID : %s\n", new_id);
            }
            else if ( ret == USER_ALREADY_EXTSTS ) { // 이미 등록된 사용자
                status[0] = (char)ret;
                send_message(clnt_sock, status, additional, key, iv);
            }
            else {
                printf("[Sign up] error occurred \n");
                status[0] = (char)ret;
                send_message(clnt_sock, status, additional, key, iv);
            }

        }

        // 로그인
        else if ( !strcmp(msg, "sign in\n") || !strcmp(msg, "sign in") ) { 
            // read id
            recv_message(clnt_sock, id, additional, key, iv, SERVER_SIDE);
            printf("id : %s\n", id);

            // read pw
            recv_message(clnt_sock, pw, additional, key, iv, SERVER_SIDE);
            printf("pw : %s\n", pw);

            ret = manage_userDB(clnt_sock, id, pw, CERT_CHECK);

            // Client Certification check (id, pw) VS (db_id, db_pw)
            if ( ret == (CORRECT_ID + CORRECT_PW) ) {
                printf("[Login success] User ID : %s\n", id);
                // send_status(ret, clnt_sock);
                status[0] = (char)ret;
                // encrypted_writen(clnt_sock, status, sizeof(status));
                send_message(clnt_sock, status, additional, key, iv);

                break;
            }
            // else if ( ret == CORRECT_ID ) { // pw 불일치
            //     continue; 
            // }
            // else if ( ret == NOT_CORRECT ) { // id 불일치
            //     continue; 
            // }
            // else { // 로그인 오류
            //     continue;
            // }
            status[0] = (char)ret;
            // encrypted_writen(clnt_sock, status, sizeof(status));
            send_message(clnt_sock, status, additional, key, iv);

        }
        else {
            break;
        }
    }

    return;
}

int manage_userDB(int sock, char* id, char* pw, int TYPE) {
    FILE *db_ptr;
    db_ptr = fopen("./FTP_Secure/userDB.txt", "rb");

    char db_id[MAX_ID_SIZE];
    char db_pw[MAX_PW_SIZE];

    int db_len;
    if (!db_ptr) {
        fopen("./FTP_Secure/userDB.txt", "w");
        db_len = 0;
    }
    else {
        fseek(db_ptr, 0, SEEK_END);
        db_len = ftell(db_ptr);
        fseek(db_ptr, 0, SEEK_SET);
    }
    char file_buf[MAX_FILE_SIZE];
    
    // Case useDB not empty
    if ( (TYPE != INSERT_USER) && (db_len > 0) ) {

        do {
            fgets(file_buf, MAX_FILE_SIZE, db_ptr);

            // read_len += db_len;
            char *tmp;
            tmp = strtok(file_buf, " ");
            do {
                strcpy(db_id, tmp);
                tmp = strtok(NULL, " ");
                strcpy(db_pw, tmp);
                tmp = strtok(NULL, " ");

                // id 일치
                if ( strcmp(id, db_id) == 0 ) { 
                    // 회원가입시에 일치 id가 있으면 --> 이미 있는 아이디
                    if ( (TYPE == EXISTS_CHECK) || (TYPE == INSERT_USER) ) {
                        fclose(db_ptr);
                        return USER_ALREADY_EXTSTS;
                    }

                    if ( TYPE == CERT_CHECK ) {
                        // pw 일치
                        if ( strcmp(db_pw, pw) == 0 ) { 
                            fclose(db_ptr);
                            return CORRECT_ID + CORRECT_PW;
                        }
                        else { // id 일치, pw 불일치 
                            fclose(db_ptr);
                            return CORRECT_ID;
                        }
                    }
                }

            } while(tmp != NULL);

        } while( !feof(db_ptr) ); // 파일 전체 읽기

    }


    // Case empty file
    fclose(db_ptr);
    if ( TYPE == EXISTS_CHECK ) { // sign up --> ok
        return USER_NOT_FOUND;
    }
    else if ( TYPE == CERT_CHECK ) { // sign in --> reject
        return NOT_CORRECT;
    }
    else if ( TYPE == INSERT_USER ) {

        db_ptr = fopen("./FTP_Secure/userDB.txt", "ab");

        const char sp = ' ';
        id[strlen(id)] = sp;
        fwrite(id, sizeof(char), strlen(id), db_ptr);
        pw[strlen(pw)] = sp;
        fwrite(pw, sizeof(char), strlen(pw), db_ptr);

        fclose(db_ptr);
        return SIGNUP_SUCCESS;
    }

    return SIGN_FAIL;
}

int handle_command(int clnt_sock) {

    // int clnt_sock = *((int*) arg);
    int str_len = 0;
    char msg[BUFSIZE], copy_msg[BUFSIZE];
    memset(&msg, 0, sizeof(msg));
    char oksign[10];

    recv_message(clnt_sock, msg, additional, key, iv, SERVER_SIDE);
    printf("\n[(handle) Client request] : %s\n", msg); //
    // if ( !strcmp(msg, '\0') ) {
    //     printf(" NULL MSG\n");
    //     error_handling("msg error");
    // }
    if ( !strcmp(msg, "") )
        return FAIL;
    
    char command[BUFSIZE], filename1[BUFSIZE], filename2[BUFSIZE];
    memset(&command, 0, sizeof(command));

    msg_split(msg, command, filename1, filename2); /* split client message */

    /* list command */
    if ( !strcmp(command, "list\n") || !strcmp(command, "list") ) {
        send_message(clnt_sock, msg, additional, key, iv);

        send_encrypted_list_msg(clnt_sock); 

        return SUCCESS;
    }
    /* up command */
    else if ( !strcmp(command, "up") || !strcmp(command, "u") ) {\
        send_message(clnt_sock, msg, additional, key, iv);

        recv_up_file(clnt_sock, filename2);

        return SUCCESS;
    }
    /* down command */
    else if ( !strcmp(command, "down") || strcmp(command, "dow") ) {
        send_message(clnt_sock, msg, additional, key, iv);

        send_down_file(clnt_sock, filename1);

        return SUCCESS;
    }

    return FAIL;
    
// err:
//     close(clnt_sock);
//     return FAIL;
}

void send_encrypted_list_msg(int clnt_sock) {

    DIR *dir;
    struct dirent *ent;
    dir = opendir ("./");
    char work_dir[256];
    getcwd(work_dir, 256);

    send_message(clnt_sock, "Working Directory : ", additional, key, iv);
    send_message(clnt_sock, work_dir, additional, key, iv);
    send_message(clnt_sock, "\nDirectory List : ", additional, key, iv);


    if (dir != NULL) {
        /* print all the files and directories within directory */
        while ( (ent = readdir(dir)) != NULL ) {
            send_message(clnt_sock, ent->d_name, additional, key, iv);
        }
        closedir(dir);
        } 
    else {
         /* could not open directory */
        printf("NULL dir\n");
        
    }
    send_message(clnt_sock, "eof", additional, key, iv);
}

void recv_up_file(int clnt_sock, char *dst_file_name) {
    char file_msg[BUFSIZE];

    recv_message(clnt_sock, file_msg, additional, key, iv, SERVER_SIDE);

    char str[BUF_SIZE];
    file_msg[strlen(file_msg)] = '\0';


    int fd = open(dst_file_name, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    memset(&str, 0, sizeof(str));
    sprintf( str, "%s", file_msg);
    write( fd, str, strlen(str));

    close(fd);
}

void send_down_file(int clnt_sock, char* file_name1) {

    // file open and send status
    FILE* ptr = fopen(file_name1, "rb");
    if (ptr == NULL) {
        return;
    }

    // 클라이언트가 요청한 파일 암호화해서 보내기
    char file_pt[BUFSIZE];
    while (!feof(ptr)) {
        fgets(file_pt, MAX_FILE_SIZE, ptr);
        send_message(clnt_sock, file_pt, additional, key, iv);
    }

}

int msg_split(char* msg, char* command, char* filename1, char* filename2) {

    if ( !msg ) {
        return FAIL;
    }


    if ( !strcmp(msg, "list\n") ) {
        strcpy(command, msg);
        return SUCCESS;
    }

	char *ptr = strtok(msg, " ");

    if (ptr != NULL) {
        strcpy(command, ptr);
		ptr = strtok(NULL, " ");
        if (ptr != NULL) {
            strcpy(filename1, ptr);
            ptr = strtok(NULL, " ");
            strcpy(filename2, ptr);
        }
	}
    return SUCCESS;
}

// EOF
