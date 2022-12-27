
#ifndef __READNWRITE_H__
#define __READNWRITE_H__

#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdio.h>

ssize_t
readn(int fd, void* vptr, size_t n);

ssize_t
writen(int fd, const void* vptr, size_t n);

#endif