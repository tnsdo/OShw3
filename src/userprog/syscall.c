#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/palloc.h"
#include "threads/init.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#define STDIN 0
#define STDOUT 1


typedef int pid_t;

_Bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  uint32_t *sp = (uint32_t *) f->esp;

  switch(sp[0]){
	  case SYS_HALT:
		  halt();
		  break;
	  case SYS_EXIT:
		  exit((int) sp[1]);
		  break;
	  case SYS_EXEC:
		  if (exec((const char *) sp[1]) == -1){
			  exit(-1);
		  }
		  break;
	  case SYS_WAIT:
		  f->eax = process_wait((pid_t) sp[1]);
		  break;
	  case SYS_CREATE:
		  f->eax = create((const char *) sp[1], (unsigned) sp[2]);
		  break;
	  case SYS_REMOVE:
		  f->eax = remove((const char *) sp[1]);
		  break;
	  case SYS_OPEN:
		  f->eax = open((const char *) sp[1]);
		  break;
	  case SYS_FILESIZE:
		  f->eax = filesize((int) sp[1]);
		  break;
	  case SYS_READ:
		  f->eax = read((int) sp[1], (void *) sp[2], (unsigned) sp[3]);
		  break;
	  case SYS_WRITE:
		  f->eax = write((int) sp[1], (const void *) sp[2], (unsigned) sp[3]);
		  break;
	  case SYS_SEEK:
		  seek((int) sp[1], (const void *) sp[2]);
		  break;
	  case SYS_TELL:
		  f->eax = tell((int) sp[1]);
		  break;
	  case SYS_CLOSE:
		  close((int) sp[1]);
		  break;
	  default:
		  exit(-1);
		  break;
  }
  //printf ("system call!\n");
  //thread_exit ();
}

void halt(void){
	shutdown_power_off();
}

void exit(int status)
{
	struct thread *t = thread_current();
	t->exit_status= status;
	printf("%s: exit%d\n", thread_name(), status);

	thread_exit();
}


pid_t exec(const char *cmd_line){
  tid_t tid;
  struct thread* t;
  tid=process_execute(cmd_line);
  t=get_child_process(tid);
  if(t!=NULL){
    sema_down(&(t->load_sema));
    if(t->load_flag==false){
      return -1;
    }
    else{
      return tid;
    }
  }
  else{
    return -1;
  }
}


void check_address(const void *addr) {
    struct thread *cur = thread_current();

    if (addr == NULL || !is_user_vaddr(addr) || pagedir_get_page(cur->pagedir, addr) == NULL) {
        exit(-1);
    }
}

int process_wait(tid_t child_tid UNUSED){
	struct thread *child = get_child_with_pid(child_tid);

	if(child == NULL)
		return -1;
	sema_down(&child->wait_sema);

	int exit_status = child->exit_status;

	list_remove(&child->child_elem);
	sema_up(&child->free_sema);

	return exit_status;
}

bool create (const char *file, unsigned initial_size) {
	check_address(file);
	return(filesys_create(file, initial_size));
}

bool remove (const char *file) {
	check_address(file);
	return(filesys_remove(file));
}

int open(const char *file){
	check_address(file);
}

int read(int fd, void *buffer, unsigned int size){
  int result;
  uint8_t temp;
  if(fd<0 || fd==1 || fd>=FDTABLE_SIZE){exit(-1);}
  lock_acquire(&filesys_lock);
  if(fd==0){
    for(result=0;(result<size) && (temp=input_getc());result++){
      *(uint8_t*)(buffer+result)=temp;
    }
  }
  else{
    struct file* f=process_get_file(fd);
    if(f==NULL){
      lock_release(&filesys_lock);
      exit(-1);
    }
    result=file_read(f, buffer, size);
  }
  lock_release(&filesys_lock);
  return result;
}

int write(int fd, const void* buffer, unsigned int size){
  int file_write_result;
  struct file* f;
  if(fd<=0 || fd>=FDTABLE_SIZE){exit(-1);}
  lock_acquire(&filesys_lock);
  if(fd==1){
    putbuf(buffer, size);
    lock_release(&filesys_lock);
    return size;
  }
  else{
    f=process_get_file(fd);
    if(f==NULL){
      lock_release(&filesys_lock);
      exit(-1);
    }
    file_write_result=file_write(f, buffer, size);
    lock_release(&filesys_lock);
    return file_write_result;
  }
}

void seek(int fd, unsigned int position){
  struct file* f=process_get_file(fd);
  if(f==NULL){exit(-1);}
  file_seek(f, position);
}

unsigned int tell(int fd){
  struct file* f=process_get_file(fd);
  if(f==NULL){exit(-1);}
  return file_tell(f);
}


void close(int fd) {
	process_close_file(fd);
}
