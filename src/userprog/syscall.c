#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/thread.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "threads/palloc.h"
#include "threads/init.h"
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

int add_file_to_fdt(struct file *file);
struct file *find_file_by_fd(int fd);
void remove_file_from_fdt(int fd);


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
	power_off();
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


void check_address(void* vaddr){
  if(vaddr==NULL){exit(-1);}
  if(!is_user_vaddr(vaddr)){exit(-1);}
  if(!pagedir_get_page(thread_current()->pagedir, vaddr)==NULL){exit(-1);}
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
	fdt[cur->fd_idx] = file;
	return cur->fd_idx;
}

int filesize(int fd){
	struct file *open_file = find_file_by_fd(fd);
	if (open_file == NULL){
		return -1;
	}
	return file_length(open_file);
}
struct file *find_file_by_fd(int fd){
	struct thread *cur = thread_current();
	if (fd < 0 || fd >= FDCOUNT_LIMIT){
		return NULL;
	}
	return cur->fd_table[fd];
}

int read(int fd, void *buffer, unsigned size) {
	check_address(buffer);

	int read_result;
	struct thread *cur = thread_current();
	struct file *file_fd = find_file_by_fd(fd);

	if (fd == 0){
		*(char *)buffer = input_getc();
		read_result = size;
	}
	else {
		if (find_file_by_fd(fd) == NULL) {
			return -1;
		}
		else {
			lock_acquire(&filesys_lock);
			read_result = file_read(find_file_by_fd(fd), buffer, size);
			lock_release(&filesys_lock);
		}
	}
	return read_result;
}

int write(int fd, const void *buffer, unsigned size) {
	check_address(buffer);

	int write_result;
	lock_acquire(&filesys_lock);
	if (fd == 1) {
		putbuf(buffer, size);
		write_result = size;
	}
	else {
		if (find_file_by_fd(fd) != NULL) {
			write_result = file_write(find_file_by_fd(fd), buffer, size);
		}
		else {
			write_result = -1;
		}
	}
	lock_release(&filesys_lock);
	return write_result;
}

void seek(int fd, unsigned position) {
	struct file *seek_file = find_file_by_fd(fd);
	if (seek_file == NULL) {
		return;
	}
	file_seek(seek_file, position);
}

unsigned tell(int fd) {
	struct file *tell_file = find_file_by_fd(fd);
	if (tell_file <= 2) {
		return;
	}
	return file_tell(tell_file);
}


void close(int fd) {
	process_close_file(fd);
}

