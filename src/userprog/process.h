#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

/* for proj2, file system */
int process_add_fd (struct file*);
struct file* process_search_file(int fd);
void process_file_close(int fd);

#endif /* userprog/process.h */

