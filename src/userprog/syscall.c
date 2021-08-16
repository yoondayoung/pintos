#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"
#include "filesys/filesys.h"

struct lock filesys_lock; // file system에 대한 lock

static void syscall_handler (struct intr_frame *);

void is_valid_user_vaddr(const void* vaddr) {
	//jf lge than PHYS_BASE, exit(-1)
	if (!is_user_vaddr(vaddr)) exit(-1);
	//if NULL or unmapped, exit(-1);
	if (vaddr == NULL || vaddr < (uint32_t*)0x08048000)exit(-1);
}

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&filesys_lock);
}

void halt(void) {
    shutdown_power_off();
}

void exit(int status) {
    thread_current()->exit_status = status;
    printf("%s: exit(%d)\n", thread_current()->name, status);
    thread_exit();
}

pid_t exec(const char* cmd_line) {
    int created_pid = process_execute(cmd_line);
    struct thread* child_process = get_child(created_pid);
    sema_down(&(child_process->load_sema));
    if (child_process->load_flag == false) return -1;
    return child_process->tid;
}

int wait(pid_t pid) {
    return process_wait(pid);
}

bool create(const char* file, unsigned initial_size) {
    if (file == NULL) exit(-1);
    return filesys_create(file, initial_size);
}

bool remove(const char* file) {
    if (file == NULL) exit(-1);
    return filesys_remove(file);
}

int open(const char* file) {
    if (file == NULL) exit(-1);
    int res = -1;
    struct file* f = filesys_open(file);
    res = process_add_fd(f);
    return res;
}

int filesize(int fd) {
    struct file* file = process_search_file(fd);
    if (file == NULL) return -1;
    else return file_length(file);
}

int read(int fd, void* buffer, unsigned size) {
    is_valid_user_vaddr(buffer);
    // 표준 입력일 경우
    if (fd == 0) {
        char* buf = buffer;
        int i;
        for (i = 0; i < size; i++) {
            buf[i] = input_getc();
        }
        return i;
    }
    // 파일 read의 경우
    struct file* file = process_search_file(fd);
    if (file == NULL) return -1;
    lock_acquire(&filesys_lock);
    int fsize = file_read(file, buffer, size);
    lock_release(&filesys_lock);
    return fsize;
}

int write(int fd, const void* buffer, unsigned size) {
    is_valid_user_vaddr(buffer);
    // 표준 출력의 경우
    if (fd == 1) {
        putbuf(buffer, size);
        return size;
    }
    // 파일 write의 경우
    struct file* file = process_search_file(fd);
    if (file == NULL) return 0;
    lock_acquire(&filesys_lock);
    int fsize = file_write(file, buffer, size);
    lock_release(&filesys_lock);
    return fsize;
}

void seek(int fd, unsigned position) {
    struct file* file = process_search_file(fd);
    if (file == NULL) return;
    file_seek(file, position);
}

unsigned tell(int fd) {
    struct file* file = process_search_file(fd);
    if (file == NULL) return -1;
    return file_tell(file);
}

void close(int fd) {
    process_file_close(fd);
}

/* extra functions */
int fibonacci(int n) {
    int f1 = 0, f2 = 1, res = -1;
    if (n <= 1) return n;
    for (int i = 2; i <= n; i++) {
        res = f1 + f2;
        f1 = f2;
        f2 = res;
    }
    return res;
}

int max_of_four_int(int a, int b, int c, int d) {
    int max;

    if (a > b) max = a; else max = b;
    if (c > max) max = c;
    if (d > max) max = d;

    return max;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{   
  is_valid_user_vaddr(f->esp);
  switch (*(uint32_t*)f->esp) {
  case SYS_HALT:
      halt();
      break;
  case SYS_EXIT:
      is_valid_user_vaddr(f->esp + 4);
      exit(*(uint32_t*)(f->esp + 4));
      break;
  case SYS_EXEC:
      is_valid_user_vaddr(f->esp + 4);
      f->eax = exec(*(uint32_t*)(f->esp + 4));
      break;
  case SYS_WAIT:
      is_valid_user_vaddr(f->esp + 4);
      f->eax = wait(*(uint32_t*)(f->esp + 4));
      break;
  case SYS_CREATE:
      is_valid_user_vaddr(f->esp + 4);
      is_valid_user_vaddr(f->esp + 8);
      f->eax = create(*(uint32_t*)(f->esp + 4), *(uint32_t*)(f->esp + 8));
      break;
  case SYS_REMOVE:
      is_valid_user_vaddr(f->esp + 4);
      f->eax = remove(*(uint32_t*)(f->esp + 4));
      break;
  case SYS_OPEN:
      is_valid_user_vaddr(f->esp + 4);
      f->eax = open(*(uint32_t*)(f->esp + 4));
      break;
  case SYS_FILESIZE:
      is_valid_user_vaddr(f->esp + 4);
      f->eax = filesize(*(uint32_t*)(f->esp + 4));
      break;
  case SYS_READ:
      is_valid_user_vaddr(f->esp + 4);
      is_valid_user_vaddr(f->esp + 8);
      is_valid_user_vaddr(f->esp + 12);
      f->eax = read(*(uint32_t*)(f->esp + 4), *(uint32_t*)(f->esp + 8), *(uint32_t*)(f->esp + 12));
      break;
  case SYS_WRITE:
      is_valid_user_vaddr(f->esp + 4);
      is_valid_user_vaddr(f->esp + 8);
      is_valid_user_vaddr(f->esp + 12);
      f->eax = write(*(uint32_t*)(f->esp + 4), *(uint32_t*)(f->esp + 8), *(uint32_t*)(f->esp + 12));
      break;
  case SYS_SEEK:
      is_valid_user_vaddr(f->esp + 4);
      is_valid_user_vaddr(f->esp + 8);
      seek(*(uint32_t*)(f->esp + 4), *(uint32_t*)(f->esp + 8));
      break;
  case SYS_TELL:
      is_valid_user_vaddr(f->esp + 4);
      f->eax = tell(*(uint32_t*)(f->esp + 4));
      break;
  case SYS_CLOSE:
      is_valid_user_vaddr(f->esp + 4);
      close(*(uint32_t*)(f->esp + 4));
      break;
  case SYS_FIBO:
      is_valid_user_vaddr(f->esp + 4);
      f->eax = fibonacci(*(uint32_t*)(f->esp + 4));
      break;
  case SYS_MAXFOUR:
      is_valid_user_vaddr(f->esp + 4);
      is_valid_user_vaddr(f->esp + 8);
      is_valid_user_vaddr(f->esp + 12);
      is_valid_user_vaddr(f->esp + 16);
      f->eax = max_of_four_int(*(uint32_t*)(f->esp + 4), *(uint32_t*)(f->esp + 8), *(uint32_t*)(f->esp + 12), *(uint32_t*)(f->esp + 16));
      break;
  }
}


