// Per-CPU state
struct cpu {
  uchar apicid;                // Local APIC ID
  struct context *scheduler;   // swtch() here to enter scheduler
  struct taskstate ts;         // Used by x86 to find stack for interrupt
  struct segdesc gdt[NSEGS];   // x86 global descriptor table
  volatile uint started;       // Has the CPU started?
  int ncli;                    // Depth of pushcli nesting.
  int intena;                  // Were interrupts enabled before pushcli?
  struct proc *proc;           // The process running on this cpu or null
};

extern struct cpu cpus[NCPU];
extern int ncpu;

//PAGEBREAK: 17
// Saved registers for kernel context switches.
// Don't need to save all the segment registers (%cs, etc),
// because they are constant across kernel contexts.
// Don't need to save %eax, %ecx, %edx, because the
// x86 convention is that the caller has saved them.
// Contexts are stored at the bottom of the stack they
// describe; the stack pointer is the address of the context.
// The layout of the context matches the layout of the stack in swtch.S
// at the "Switch stacks" comment. Switch doesn't save eip explicitly,
// but it is on the stack and allocproc() manipulates it.
struct context {
  uint edi;
  uint esi;
  uint ebx;
  uint ebp;
  uint eip;
};

enum procstate { UNUSED, EMBRYO, SLEEPING, RUNNABLE, RUNNING, ZOMBIE };


// Process memory is laid out contiguously, low addresses first:
//   text
//   original data and bss
//   fixed-size stack
//   expandable heap



/* ====== task1 pages stuff =======  */
#include "pages_def.h"

struct pages {
    int count;
    uint va[MAX_TOTAL_PAGES];
    memory_location location[MAX_TOTAL_PAGES];
    uint accesses[MAX_TOTAL_PAGES];
};

struct diskPage{
    char elements;
    uint va;
};


struct fifoQueue {
	char elements[MAX_PSYC_PAGES];
	uint va[MAX_PSYC_PAGES];
	int first;
	int last;
	int count;
};

struct agingQueueNode {
  int page_index;
  struct agingQueueNode * prev;
  struct agingQueueNode * next;
};

struct agingQueueNode * aq_head;
struct agingQueueNode * aq_tail;

// Per-process state
struct proc {
  uint sz;                     // Size of process memory (bytes)
  pde_t* pgdir;                // Page table
  char *kstack;                // Bottom of kernel stack for this process
  enum procstate state;        // Process state
  int pid;                     // Process ID
  struct proc *parent;         // Parent process
  struct trapframe *tf;        // Trap frame for current syscall
  struct context *context;     // swtch() here to run process
  void *chan;                  // If non-zero, sleeping on chan
  int killed;                  // If non-zero, have been killed
  struct file *ofile[NOFILE];  // Open files
  struct inode *cwd;           // Current directory
  char name[16];               // Process name (debugging)

  //Swap file. must initiate with create swap file
  struct file *swapFile;      //page file

  // === Task 1 pages stuff. ===
  // Proc's memory pages.
  struct pages pages;
  // Pages on the disk
  struct diskPage diskPages[MAX_TOTAL_PAGES - MAX_PSYC_PAGES];
  // number of page faults
  uint page_faults;
  // number of pages in the disk
  uint pages_on_disk;
  // total number of paged out pages
  uint total_pages_on_disk;
  // ====================== TASK 2
  struct fifoQueue fifoQueue;
};
