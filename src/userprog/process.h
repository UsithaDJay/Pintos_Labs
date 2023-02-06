#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "threads/synch.h"
typedef int proID_t;


tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

//The description of files are kept in this structure
struct description_of_files
{
    int ID;
    struct list_elem elem;
    struct file* file;
};

//contol_block of the processes are kept here
struct  control_block_for_process 
{
  proID_t proID;
  int32_t exitcode; 
  struct semaphore sema_init; 
  struct semaphore sema_wait; 
  struct thread* t_parent;  
  const char* command_line;      
  struct list_elem elem;    
  bool thread_waiting;            
  bool thread_exited;            
  
};


#endif /* userprog/process.h */