#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
typedef int pid_t;


tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

//This struct keeps the file_descriptor
struct file_desc
{
    int id;
    struct list_elem elem;
    struct file* file;
};

//Keeps the process_control_block
struct  process_control_block 
{
  pid_t pid;
  const char* cmdline;      
  struct list_elem elem;    
  struct thread* parent_thread;   
  bool waiting;            
  bool exited;            
  int32_t exitcode;        
  struct semaphore sema_init; 
  struct semaphore sema_wait; 

};


#endif /* userprog/process.h */