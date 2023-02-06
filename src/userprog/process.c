#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/synch.h"

static thread_func start_process NO_RETURN;
static bool load (const char *command_line, void (**eip) (void), void **esp);

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created. */

tid_t
process_execute (const char *file_name) 
{
  char *fn_copy;
  tid_t tid;

   /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  

  fn_copy = palloc_get_page (0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy (fn_copy, file_name, PGSIZE);

  char *name_of_the_command;
  char *pointer_save;
  
  //The first splitted string is available here
  name_of_the_command =strtok_r (file_name, " ", &pointer_save); 

  struct control_block_for_process* pro_con_block = palloc_get_page(0);

  //Assign -1 as process ID
  pro_con_block->proID = -1;

  //Assign the current thread to the parent thread
  pro_con_block->t_parent = thread_current();
  
  //Initialize the semaphore sema_init to 0
  sema_init(&pro_con_block->sema_init, 0);
  
  //Initialize the semaphore sema_wait to 0
  sema_init(&pro_con_block->sema_wait, 0);

  pro_con_block->thread_waiting = false;
  pro_con_block->thread_exited = false;

  pro_con_block->command_line = fn_copy;

   /* Create a new thread to execute FILE_NAME. */ 
  tid = thread_create(name_of_the_command, PRI_DEFAULT, start_process, pro_con_block);
  
  sema_down(&pro_con_block->sema_init);
    // Wait on the semaphore pro_con_block->sema_init

  if (tid == TID_ERROR)
    // Check if the thread creation was not successful
    
    palloc_free_page (fn_copy); 
    // Free the allocated page for the function copy if thread creation was not successful

  if (tid == -1){
    // Check if the thread creation was not successful
    
    palloc_free_page (pro_con_block);
    // Free the allocated page for the pro_con_block if thread creation was not successful
    return -1;
    // Return -1 as an error indicator
  }
  list_push_back(&thread_current()->list_of_pcbs, &pro_con_block->elem); 
  // Push the pro_con_block to the list of pcb's of the current thread

  return tid;
  // Return the thread ID of the newly created thread
}

/* A thread function that loads a user process and starts it
   running. */

static void
start_process (void *file_name_)
// Definition of the start_process function, which takes a void pointer as input
{
  struct control_block_for_process* pro_con_block = file_name_;
  // Typecast the void pointer to a pointer to a struct control_block_for_process
  // And store the result in the variable pro_con_block

  char *file_name = pro_con_block->command_line;
  // Get the command line from the struct control_block_for_process and store it in file_name
  
  struct intr_frame if_;
  // Declare a struct intr_frame if_
  bool success;

  
  char *fetched_arguments[50];
  // Declare an array of pointers to characters named fetched_arguments with a capacity of 50

  char count = 0;
  char *string_splitted,*pointer_save;
  // Declare two pointers to characters string_splitted and pointer_save

  
  for (string_splitted = strtok_r(file_name," ",&pointer_save);string_splitted != NULL;
  string_splitted = strtok_r(NULL," ",&pointer_save)) {
      fetched_arguments[count++]=string_splitted;
      // Split the file_name string into tokens using " " as the delimiter
      // Store each token in the fetched_arguments array and increment the count
  }

  /*Initialize interrupt frame and load executable.*/
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  success = load (file_name, &if_.eip, &if_.esp);

  
  if (success) {
    pro_con_block->proID = thread_current()->tid;
    // Store the ID of the current thread in the proID field of the pro_con_block
  
    thread_current()->thread_pcbs = pro_con_block; 
    // Store the pro_con_block in the thread_pcbs field of the current thread
  
    creation_of_stack_for_arguments(fetched_arguments,count,&if_.esp);
    
  }

  
  sema_up(&pro_con_block->sema_init);

  // palloc_free_page (file_name);
  if (!success) 
    thread_exit ();

  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
   // Move the address of the struct intr_frame if_ to the esp register and jump to the intr_exit function
  NOT_REACHED ();
}



  //This function will create the argument stack
  creation_of_stack_for_arguments(char **arguments,int count,void **esp){
    
    int array_of_argument_address[count];
     // Array to store the addresses of the arguments
    int size;
    // Size variable to store the length of each argument

    //Setting up address array
    for (int i =count-1 ;i>=0;i--)
    {
      size  = strlen(arguments[i])+1;
      // Calculate the size of the current argument
      
      *esp -= size;
       // Decrement the esp by the size of the current argument

      memcpy(*esp,arguments[i],size);
      // Copy the current argument to the address pointed to by esp
      
      array_of_argument_address[i] = (int)*esp;
      // Store the address of the current argument in the array_of_argument_address
      
    }  
      *esp = (int)*esp & 0xfffffffc;
      // Align the esp to a 4-byte boundary
      *esp -= 4;
      *(int*)*esp = 0;
      // Align the esp to a 4-byte boundary

      for (int i=count-1; i>=0;i--){
        *esp -= 4;
        *(int*)*esp = array_of_argument_address[i];
        // Push the address of each argument to the stack in reverse order
      }
    
      *esp -= 4;
      *(int*)*esp = (int)*esp + 4;
      // Push the address of the first argument to the stack

      *esp -= 4;
      *(int*)*esp = count;
      // Push the argument count to the stack

      *esp -= 4;
      *(int*)*esp = 0;
      // Push a 0 to the stack as the return address
      
  }



/* Waits for thread tid to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If tid is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given tid, returns -1
   immediately, without thread_waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int
process_wait (tid_t child_tid UNUSED) 
{
  struct list* list_of_pcbs = &thread_current()->list_of_pcbs;
  // Create a pointer to the list of child process control blocks in the current thread

  struct list_elem* e;
  // Create a pointer to traverse the list

  struct control_block_for_process* pro_con_block;
  // Create a pointer to a child process control block

  for (e = list_begin (list_of_pcbs); e != list_end (list_of_pcbs); e = list_next (e)){
    pro_con_block = list_entry(e, struct control_block_for_process, elem);
    if(pro_con_block->proID == child_tid) break;
  }
  // Find the control block of the specified child process in the list

  
  if(pro_con_block == NULL || pro_con_block->proID != child_tid || pro_con_block->thread_waiting || pro_con_block->thread_exited) return -1;

  pro_con_block->thread_waiting = true;
  // Find the control block of the specified child process in the list


  sema_down(&pro_con_block->sema_wait);
  // Wait until the child process signals that it has exited

  list_remove(&pro_con_block->elem);
  // Remove the control block from the list of child process control blocks

  return pro_con_block->exitcode;
  // Return the exit code of the child process

}

void
process_exit (void)
{
  struct thread *cur = thread_current ();
  // Get the current thread

  uint32_t *pd;
  // pointer to page directory

  struct list* list_of_pcbs = &cur->list_of_pcbs;
  // Get the list of process control blocks associated with the current thread

  struct control_block_for_process* pro_con_block;
  // process control block of a child process

  while(!list_empty(list_of_pcbs)) {
    pro_con_block = list_pop_back(list_of_pcbs);
    // remove the last process control block from the list

    if(!pro_con_block->thread_exited){// if the child process has not exited
      pro_con_block->t_parent = NULL;
      // set the parent process to NULL

    }else{
      palloc_free_page(pro_con_block);
      // free the page occupied by the process control block
    }
  }
  if(cur->thread_pcbs != NULL){// if the current thread has a process control block associated with it
    cur->thread_pcbs->thread_exited = true;// mark the thread as exited
    sema_up(&cur->thread_pcbs->sema_wait);// signal the semaphore for the waiting parent process

    if(cur->thread_pcbs->t_parent == NULL)// if the parent process is not present
      palloc_free_page(cur->thread_pcbs);// free the page occupied by the process control block
  }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pagedir;
  if (pd != NULL) 
    {
      /* Correct ordering here is crucial.  We must set
         cur->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
      cur->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();

  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
  {
    unsigned char e_ident[16];
    Elf32_Half    e_type;
    Elf32_Half    e_machine;
    Elf32_Word    e_version;
    Elf32_Addr    e_entry;
    Elf32_Off     e_phoff;
    Elf32_Off     e_shoff;
    Elf32_Word    e_flags;
    Elf32_Half    e_ehsize;
    Elf32_Half    e_phentsize;
    Elf32_Half    e_phnum;
    Elf32_Half    e_shentsize;
    Elf32_Half    e_shnum;
    Elf32_Half    e_shstrndx;
  };

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
  {
    Elf32_Word p_type;
    Elf32_Off  p_offset;
    Elf32_Addr p_vaddr;
    Elf32_Addr p_paddr;
    Elf32_Word p_filesz;
    Elf32_Word p_memsz;
    Elf32_Word p_flags;
    Elf32_Word p_align;
  };

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool setup_stack (void **esp);
static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (const char *file_name, void (**eip) (void), void **esp) 
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL) 
    goto done;
  process_activate ();

  /* Open executable file. */
  file = filesys_open (file_name);
  if (file == NULL) 
    {
      printf ("load: %s: open failed\n", file_name);
      goto done; 
    }

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024) 
    {
      printf ("load: %s: error loading executable\n", file_name);
      goto done; 
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) 
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      switch (phdr.p_type) 
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (validate_segment (&phdr, file)) 
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                     Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else 
                {
                  /* Entirely zero.
                     Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (esp))
    goto done;

  /* Start address. */
  *eip = (void (*) (void)) ehdr.e_entry;

  success = true;

 done:
  /* We arrive here whether the load is successful or not. */
  file_close (file);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file) 
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK)) 
    return false; 

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file)) 
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz) 
    return false; 

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;
  
  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ((void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ((void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable) 
{
  ASSERT ((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  file_seek (file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) 
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* Get a page of memory. */
      uint8_t *kpage = palloc_get_page (PAL_USER);
      if (kpage == NULL)
        return false;

      /* Load this page. */
      if (file_read (file, kpage, page_read_bytes) != (int) page_read_bytes)
        {
          palloc_free_page (kpage);
          return false; 
        }
      memset (kpage + page_read_bytes, 0, page_zero_bytes);

      /* Add the page to the process's address space. */
      if (!install_page (upage, kpage, writable)) 
        {
          palloc_free_page (kpage);
          return false; 
        }

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
    }
  return true;
}

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool
setup_stack (void **esp) 
{
  uint8_t *kpage;
  bool success = false;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage != NULL) 
    {
      success = install_page (((uint8_t *) PHYS_BASE) - PGSIZE, kpage, true);
      if (success)
        *esp = PHYS_BASE;
      else
        palloc_free_page (kpage);
    }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
