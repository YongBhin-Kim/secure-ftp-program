# aestest, evptest makefile


CC		= gcc
LDFLAGS	= -lcrypto

UTIL_SRCS		= FTP_Util/readnwrite.c FTP_Util/aesenc.c FTP_Util/secure_communication.c
UTIL_HEADERS 	= FTP_Util/readnwrite.h FTP_Util/aesenc.h FTP_Util/msg.h FTP_Util/secure_communication.h

SERVER 		= FTP_Server/server
SERVER_SRCS = FTP_Server/server.c

CLIENT 		= FTP_Client/client
CLIENT_SRCS = FTP_Client/client.c

all : $(SERVER) $(CLIENT)

$(SERVER): $(SERVER_SRCS) $(UTIL_SRCS) $(UTIL_HEADERS)
	$(CC) -o $@ $(SERVER_SRCS) $(UTIL_SRCS) $(LDFLAGS) $(CPPFLAGS)

$(CLIENT): $(CLIENT_SRCS) $(UTIL_SRCS) $(UTIL_HEADERS)
	$(CC) -o $@ $(CLIENT_SRCS) $(UTIL_SRCS) $(LDFLAGS) $(CPPFLAGS)


clean:
	rm -rf $(SERVER) 
	rm -rf $(CLIENT)