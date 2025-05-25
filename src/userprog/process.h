#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#define LIMIT FDCOUNT_LIMIT

#include "threads/thread.h"
#include "threads/interrupt.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

void construct_stack(const char* file_name, void** esp);
struct thread *get_child_process(int pid);
void process_close_file(int fd);
int process_add_file(struct file *f);
struct file *process_get_file(int fd);
void process_close_file(int fd);
#endif /* userprog/process.h */
