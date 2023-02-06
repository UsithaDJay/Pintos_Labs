#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "kernel/stdio.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "threads/synch.h"
#include "filesys/filesys.h"
#include "threads/malloc.h"
#include "threads/vaddr.h"


typedef int proID_t;


struct lock file_sys_lock;
struct description_of_files* get_description_of_files(int fd);


int isuser(void* pointer, void* destination, size_t size);
static int get_user (const uint8_t *uaddr);
static void syscall_handler (struct intr_frame *);


void halt(void);
void exit (int exit_status);
proID_t exec(const char* cmd_line);
int wait(proID_t proID);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);



struct description_of_files* get_description_of_files(int fd) {
  if(fd < 3){
    return NULL;
  }
  
  struct list* list_of_files= &thread_current()-> list_of_files;
  struct list_elem*e;
  for (e = list_begin (list_of_files); e != list_end(list_of_files); e = list_next (e)){
    struct description_of_files* fds = list_entry(e, struct description_of_files, elem);
    if(fds->ID == fd){
      return fds;
    }
  }
  return NULL;
}



//Use to validate
int isuser(void* pointer, void* destination, size_t size) {
  int32_t  val;
  size_t i;
  for(i = 0; i < size; i++){
    val = get_user(pointer + i);
    if(val == -1){
      exit(-1);
    }
    *(char*) (destination + i) = val & 0xff;
  }
  return (int) size;
}


static int
get_user (const uint8_t *uaddr)
{
    if ((void*)uaddr >= PHYS_BASE)
      return -1; 
    int ret;
    asm ("movl $1f, %0; movzbl %1, %0; 1:"
        : "=&a" (ret) : "m" (*uaddr));
    return ret;
}



void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init(&file_sys_lock);
}


//This function handles the commands
static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int number;
  if(isuser(f->esp, &number, sizeof(number)) == -1) {
    exit(-1);
  }
  switch (number)
  {
  case SYS_HALT:{
    halt();
    break;
  }

  case SYS_EXIT:{
    int exit_status;
    if(isuser(f->esp + 4, &exit_status, sizeof(exit_status)) == -1) {
      exit(-1);
    }
    exit(exit_status);
    break;
  }

  case SYS_EXEC: {
    const char* cmd_line;
    
    if(isuser(f->esp + 4, &cmd_line, sizeof(cmd_line)) == -1) {
      exit(-1);
    }
    f->eax =  exec(cmd_line);
    break;
  }

  case SYS_CREATE:{
    char* file;
    unsigned initial_size;

    if(isuser(f->esp + 4, &file, sizeof(file)) == -1) {
      exit(-1);
    }
    if(isuser(f->esp + 8, &initial_size, sizeof(initial_size)) == -1) {
      exit(-1);
    }
    f->eax = create(file, initial_size);
    break;
  }

  case SYS_OPEN: {
    char* file;
    if(isuser(f->esp + 4, &file, sizeof(file)) == -1) {
      exit(-1);
    }
    f->eax = (uint32_t)open(file);
    break;
  }

  case SYS_SEEK: {
    int fd;
    unsigned position;
    if(isuser(f->esp + 4, &fd, sizeof(fd)) == -1) {
      exit(-1);
    }

    if(isuser(f->esp + 8, &position, sizeof(position)) == -1) {
      exit(-1);
    }
    seek(fd, position);
    break;
  }

  case SYS_FILESIZE:{
    int fd;
    if(isuser(f->esp + 4, &fd, sizeof(fd)) == -1) {
      exit(-1);
    }
    f->eax = (uint32_t)filesize(fd);
    break;
  }

  case SYS_READ: {
    int fd;
    void * buffer;
    unsigned int size;

    if(isuser(f->esp + 4, &fd, sizeof(fd)) == -1) {
      exit(-1);
    }
    if(isuser(f->esp + 8, &buffer, sizeof(buffer)) == -1) {
      exit(-1);
    }
    if(isuser(f->esp + 12, &size, sizeof(size)) == -1) {
      exit(-1);
    }
    f->eax = (uint32_t)read(fd, buffer, size);
    break;
  }

  case SYS_WRITE:{
    int fd;
    void* buffer;
    unsigned int size;

    if(isuser(f->esp + 4, &fd, sizeof(fd)) == -1) {
      exit(-1);
    }
    if(isuser(f->esp + 8, &buffer, sizeof(buffer)) == -1) {
      exit(-1);
    }
    if(isuser(f->esp + 12, &size, sizeof(size)) == -1) {
      exit(-1);
    }
    f->eax = (uint32_t)write(fd, buffer, size);
    break;
  }

  case SYS_TELL: {
    int fd;
    if(isuser(f->esp + 4, &fd, sizeof(fd)) == -1) {
      exit(-1);
    }
    f->eax = (uint32_t)tell(fd);
    break;
  }

  case SYS_CLOSE: {
    int fd;
    if(isuser(f->esp + 4, &fd, sizeof(fd)) == -1) {
      exit(-1);
    }
    close(fd);
    break;
  }

  case SYS_WAIT: {
    proID_t proID;
    if(isuser(f->esp + 4, &proID, sizeof(proID)) == -1) {
      exit(-1);
    }
    f->eax = (uint32_t)wait(proID);
    break;
  }

  case SYS_REMOVE:{
    char* file;
    if(isuser(f->esp + 4, &file, sizeof(file)) == -1) {
      exit(-1);
    }
    f->eax = remove(file);
    break;
  }

  default:{
    printf("Invalid command.");
    break;
  }
  }
}



void halt(void) {
  shutdown_power_off();
}


void exit (int exit_status)
{
    // Get the current thread
    struct thread *curr = thread_current (); 
    
    // Set the exit code of the current thread
    curr->thread_pcbs->exitcode = exit_status;
    
    // Print the exit status and name of the current thread
    printf("%s: exit(%d)\n" , curr -> name , exit_status);
    
    // Exit the current thread
    thread_exit();
}


// exec() function to execute a command line and return the process id
proID_t exec(const char* cmd_line) {

  // Loop through the command line string
  int i = 0; 
  while (i < sizeof(cmd_line)) { 
    // If user memory access is not allowed
    if (get_user(cmd_line + i) == -1){ 
      // Exit with error code -1
      exit(-1); 
    } 
    i++; 
  } 

  // If cmd_line is not a valid string
  if(!cmd_line)
  {
    return -1;
  }

  lock_acquire(&file_sys_lock);

  // Execute the command line
  proID_t child_tid = process_execute(cmd_line);

  lock_release(&file_sys_lock);
  return child_tid;
}


int wait(proID_t proID) {
  return process_wait(proID);
}


bool create(const char *file, unsigned initial_size){
  // Check if the file has access to read
  if (get_user(file) == -1) exit(-1);

  lock_acquire(&file_sys_lock);

  // Create file
  bool file_status = filesys_create(file, initial_size);

  lock_release(&file_sys_lock);
  return file_status;
}


//Remove the file specified by file. Returns true if success, false otherwise
bool remove(const char *file){
  lock_acquire(&file_sys_lock);

  // Call filesys_remove function to remove the file
  bool isRemoved = filesys_remove(file);

  lock_release(&file_sys_lock);
  return isRemoved;
}


// Open file 'file' and return file descriptor ID
int open(const char *file) {
  // Check if file pointer is null
  if(!file) return -1;

  lock_acquire(&file_sys_lock);
  struct file* fo = filesys_open(file);

  // Check if file was not opened successfully
  if(!fo) {
    lock_release(&file_sys_lock);
    return -1;
  }

  // Allocate memory for file descriptor container
  struct description_of_files *new_FD = malloc(sizeof(struct description_of_files));
  // Set file in file descriptor
  new_FD->file = fo;
  // Get list of files for current thread
  struct list* list_of_files = &thread_current()->list_of_files;
  // If list is empty, set file descriptor ID to 3
  if(list_empty(list_of_files)) {
    new_FD->ID = 3;
  } else {
    // Get file descriptor from end of list
    struct description_of_files* file_des = list_entry(list_back(list_of_files), struct description_of_files, elem);
    // Increment file descriptor ID by 1
    new_FD->ID = file_des->ID + 1;
  }

  // Push file descriptor to list of files
  list_push_back(list_of_files, &new_FD->elem);

  lock_release(&file_sys_lock);
  return new_FD->ID;
}


// Returns the size of the file identified by file descriptor fd.
// Returns -1 if file descriptor is invalid
int filesize(int fd){

  // Get the file description 
  struct description_of_files* file_des = get_description_of_files(fd);

  // If the file description is invalid, return -1
  if(file_des == NULL) return -1;

  lock_acquire(&file_sys_lock);

  // Get the length of the file
  off_t len = file_length(file_des->file);

  lock_release(&file_sys_lock);
  return len;
}


int read(int fd, void *buffer, unsigned size){
  // Validate user buffer access
  if (get_user(buffer) == -1 || get_user(buffer + size - 1) == -1)
  {
    exit(-1);
  }

  lock_acquire(&file_sys_lock);

  // If file descriptor is 0, read from input
  if (fd == 0)
  {
    lock_release(&file_sys_lock);
    return (int) input_getc();
  }

  // Check if file list is empty or if fd is invalid
  if (list_empty(&thread_current()->list_of_files) || fd == 2 || fd == 1)
  {
    lock_release(&file_sys_lock);
    return -1;
  }

  // Find file with matching file descriptor
  struct list_elem*temp_elem;
  for (temp_elem = list_front(&thread_current()->list_of_files); temp_elem != NULL; temp_elem = temp_elem->next)
  {
      struct description_of_files *tem = list_entry(temp_elem, struct description_of_files, elem);
      if (tem->ID == fd)
      {
        lock_release(&file_sys_lock);
        int tot_bytes = (int) file_read(tem->file, buffer, size);
        return tot_bytes;
      }
  }

  lock_release(&file_sys_lock);
  return -1;
}


int write(int fd, const void *buffer, unsigned size){
  //Check if the buffer's memory address is valid
  if (get_user(buffer) == -1 || get_user(buffer + size) == -1) exit(-1);
  //if fd is 1, write to console  
  if(fd == 1){
    putbuf((const char*)buffer, size);
    return size;
  }
  //get the description of the file from the file descriptor
  struct description_of_files* file_des = get_description_of_files(fd);
  //if invalid file descriptor, return -1
  if(file_des == NULL){
    return -1;
  }
  lock_acquire(&file_sys_lock);
  int tot_bytes = (int) file_write(file_des->file, buffer, size);
  lock_release(&file_sys_lock);
  return tot_bytes;
}


void seek(int fd, unsigned position) {
  // Get the file descriptor
  struct description_of_files* file_des = get_description_of_files(fd);
  // return if not found
  if(file_des == NULL) return;
  lock_acquire(&file_sys_lock);
  // Seek the file to the given position
  file_seek(file_des->file, position);
  lock_release(&file_sys_lock);
}


unsigned tell(int fd){
  // Get the file descriptor
  struct description_of_files* file_des = get_description_of_files(fd);
  // If null return -1
  if(file_des == NULL) return -1;

  lock_acquire(&file_sys_lock);
  // Get the current position of the file
  off_t tll = file_tell(file_des->file);
  lock_release(&file_sys_lock);
  // return the current position
  return tll;
}


void close(int fd) {
  // Get the file descriptor
  struct description_of_files* file_des = get_description_of_files(fd);
  // If NULL return
  if(file_des == NULL) return;
  lock_acquire(&file_sys_lock);
  // Close File
  file_close(file_des->file);
  // Remove the file from the list of files
  list_remove(&file_des->elem);
  // Deallocate memory
  free(file_des);
  lock_release(&file_sys_lock); 
}
