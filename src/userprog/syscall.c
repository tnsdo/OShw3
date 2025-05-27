#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/filesys.h"


static void syscall_handler (struct intr_frame *);
pid_t tid;

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}

static void
syscall_handler (struct intr_frame *f UNUSED)
{
  switch(*(int32_t*)(f->esp)){
    case SYS_HALT:
    	halt();
    	break;
    case SYS_EXIT:
	check_address(f->esp+4);
    	exit(*(int*)(f->esp+4));
    	break;
    case SYS_EXEC:
    	check_address(f->esp+4);
    	f->eax=exec((char*)*(uint32_t*)(f->esp+4));
    	break;
    case SYS_WAIT:
    	check_address(f->esp+4);
    	f->eax = wait(*(uint32_t*)(f->esp+4));
    	break;
    case SYS_CREATE:
    	check_address(f->esp+4);
    	check_address(f->esp+8);
    	f->eax = create((char*)*(uint32_t*)(f->esp+4), *(uint32_t*)(f->esp+8));
    	break;
    case SYS_REMOVE:
    	check_address(f->esp+4);
    	f->eax = remove((char*)*(uint32_t*)(f->esp+4));
    	break;
    case SYS_OPEN:
    	check_address(f->esp+4);
    	f->eax = open((char*)*(uint32_t*)(f->esp+4));
    	break;
    case SYS_FILESIZE:
	check_address(f->esp+4);
    	f->eax = filesize(*(uint32_t*)(f->esp+4));
    	break;
    case SYS_READ:
	check_address(f->esp+4);
    	check_address(f->esp+8);
    	check_address(f->esp+12);
    	f->eax = read((int)*(uint32_t*)(f->esp+4), (void*)*(uint32_t*)(f->esp+8),(unsigned)*(uint32_t*)(f->esp+12));
    	break;
    case SYS_WRITE:    
	check_address(f->esp+4);
    	check_address(f->esp+8);
    	check_address(f->esp+12);
    	f->eax = write((int)*(uint32_t*)(f->esp+4), (const void*)*(uint32_t*)(f->esp+8),(unsigned)*(uint32_t*)(f->esp+12));
    	break;
    case SYS_SEEK:    
	check_address(f->esp+4);
	check_address(f->esp+8);
    	seek((int)*(uint32_t*)(f->esp+4), (unsigned)*(uint32_t*)(f->esp+8));
    	break;
    case SYS_TELL:
	check_address(f->esp+4);
    	f->eax = tell((int)*(uint32_t*)(f->esp+4));
    	break;
    case SYS_CLOSE:
	check_address(f->esp+4);
    	close(*(uint32_t*)(f->esp+4));
    	break;
  }
  //printf ("system call! %d\n", *(int32_t*)(f->esp));
  //thread_exit ();
}

void check_address(const void *vaddr){
  if (vaddr == NULL || !is_user_vaddr(vaddr) ||
      pagedir_get_page(thread_current()->pagedir, vaddr) == NULL) {
  exit(-1);
  }
}


void halt(void){
  shutdown_power_off();
}

void exit(int status){
  struct thread *t=thread_current();
  printf("%s: exit(%d)\n", thread_name(), status);
  t->exit_status=status;
  thread_exit();
}


pid_t exec(const char *cmd_line){
	process_execute(cmd_line);
}

int wait(pid_t pid){
  return process_wait(pid);
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

int open(const char* file){
  int fd;
  struct file* f;
  if(file==NULL){exit(-1);}
  lock_acquire(&filesys_lock);
  f=filesys_open(file);
  if(f==NULL){
    lock_release(&filesys_lock);
    return -1;
  }
  fd=process_add_file(f);
  lock_release(&filesys_lock);
  return fd;
}

bool create(const char *file, unsigned initial_size){
  if(file==NULL){
    exit(-1);
  }
  return filesys_create(file, initial_size);
}

bool remove(const char *file){
  if(file==NULL){
    exit(-1);
  }
  return filesys_remove(file);
}
void close(int fd){
  process_close_file(fd);
}

int filesize(int fd){
  struct file* f=process_get_file(fd);
  if(f==NULL){exit(-1);}
  return file_length(f);
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
