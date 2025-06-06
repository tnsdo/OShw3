#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include <stdbool.h>

typedef int pid_t;

void syscall_init (void);


void check_address(const void* vaddr);
void halt(void);
void exit(int status);
pid_t exec(const char *cmd_line);
int wait(pid_t pid);
bool create(const char* file, unsigned int initial_size);
bool remove(const char* file);
int open(const char* file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned int size);
int write(int fd, const void* buffer, unsigned int size);
void seek(int fd, unsigned int position);
unsigned int tell(int fd);
void close(int fd);
struct lock filesys_lock;
#endif /* userprog/syscall.h */
