#include "types.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "mmu.h"
#include "x86.h"
#include "proc.h"
#include "spinlock.h"

struct {
  struct spinlock lock;
  struct proc proc[NPROC];
} ptable;

static struct proc *initproc;

int nextpid = 1;
extern void forkret(void);
extern void trapret(void);

static void wakeup1(void *chan);

void
pinit(void)
{
  initlock(&ptable.lock, "ptable");
}

// Must be called with interrupts disabled
int
cpuid() {
  return mycpu()-cpus;
}

// Must be called with interrupts disabled to avoid the caller being
// rescheduled between reading lapicid and running through the loop.
struct cpu*
mycpu(void)
{
  int apicid, i;

  if(readeflags()&FL_IF)
    panic("mycpu called with interrupts enabled\n");

  apicid = lapicid();
  // APIC IDs are not guaranteed to be contiguous. Maybe we should have
  // a reverse map, or reserve a register to store &cpus[i].
  for (i = 0; i < ncpu; ++i) {
    if (cpus[i].apicid == apicid)
      return &cpus[i];
  }
  panic("unknown apicid\n");
}

// Disable interrupts so that we are not rescheduled
// while reading proc from the cpu structure
struct proc*
myproc(void) {
  struct cpu *c;
  struct proc *p;
  pushcli();
  c = mycpu();
  p = c->proc;
  popcli();
  return p;
}

//PAGEBREAK: 32
// Look in the process table for an UNUSED proc.
// If found, change state to EMBRYO and initialize
// state required to run in the kernel.
// Otherwise return 0.
static struct proc*
allocproc(void)
{
    struct proc *p;
    char *sp;

    acquire(&ptable.lock);

    for(p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if(p->state == UNUSED)
        goto found;

    release(&ptable.lock);
    return 0;

    found:
    p->state = EMBRYO;
    p->pid = nextpid++;

    release(&ptable.lock);

    // Allocate kernel stack.
    if((p->kstack = kalloc()) == 0){
    p->state = UNUSED;
    return 0;
    }
    // Task 1.
    pagesCounter++;
    sp = p->kstack + KSTACKSIZE;

    // Leave room for trap frame.
    sp -= sizeof *p->tf;
    p->tf = (struct trapframe*)sp;

    // Set up new context to start executing at forkret,
    // which returns to trapret.
    sp -= 4;
    *(uint*)sp = (uint)trapret;

    sp -= sizeof *p->context;
    p->context = (struct context*)sp;
    memset(p->context, 0, sizeof *p->context);
    p->context->eip = (uint)forkret;

    // Task 1 - set initial values.
    p->page_faults = 0;
    p->pages_on_disk = 0;
    p->total_pages_on_disk = 0;

  return p;
}

//PAGEBREAK: 32
// Set up first user process.
void
userinit(void)
{
  struct proc *p;
  extern char _binary_initcode_start[], _binary_initcode_size[];

  p = allocproc();

  initproc = p;
  if((p->pgdir = setupkvm()) == 0)
    panic("userinit: out of memory?");
  inituvm(p->pgdir, _binary_initcode_start, (int)_binary_initcode_size);
  p->sz = PGSIZE;
  memset(p->tf, 0, sizeof(*p->tf));
  p->tf->cs = (SEG_UCODE << 3) | DPL_USER;
  p->tf->ds = (SEG_UDATA << 3) | DPL_USER;
  p->tf->es = p->tf->ds;
  p->tf->ss = p->tf->ds;
  p->tf->eflags = FL_IF;
  p->tf->esp = PGSIZE;
  p->tf->eip = 0;  // beginning of initcode.S

  safestrcpy(p->name, "initcode", sizeof(p->name));
  p->cwd = namei("/");

  // this assignment to p->state lets other cores
  // run this process. the acquire forces the above
  // writes to be visible, and the lock is also needed
  // because the assignment might not be atomic.
  acquire(&ptable.lock);

  p->state = RUNNABLE;

  release(&ptable.lock);
}

// Grow current process's memory by n bytes.
// Return 0 on success, -1 on failure.
int
growproc(int n)
{
  uint sz;
  struct proc *curproc = myproc();

  sz = curproc->sz;
  if(n > 0){
    if((sz = allocuvm(curproc->pgdir, sz, sz + n)) == 0)
      return -1;
  } else if(n < 0){
    if((sz = NewDeallocuvm(curproc->pgdir, sz, sz + n)) == 0)
      return -1;
  }
  curproc->sz = sz;
  switchuvm(curproc);
  return 0;
}

// Create a new process copying p as the parent.
// Sets up stack to return as if from system call.
// Caller must set state of returned proc to RUNNABLE.
int
fork(void)
{
  int i, pid;
  struct proc *np;
  struct proc *curproc = myproc();

  // Allocate process.
  if((np = allocproc()) == 0){
    return -1;
  }

    // Copy process state from proc.
    // task 1- page information
    np->pages_on_disk = curproc->pages_on_disk;
    np->total_pages_on_disk = curproc->total_pages_on_disk;
    // copy data from original process
    ;
    for (int copyPageIndex = 0; copyPageIndex < MAX_TOTAL_PAGES; ++copyPageIndex) {
      np->pages.va[copyPageIndex] = curproc->pages.va[copyPageIndex];
      np->pages.location[copyPageIndex] = curproc->pages.location[copyPageIndex];
      np->pages.count = curproc->pages.count;
    }
    if((np->pgdir = copyuvm(curproc->pgdir, curproc->sz)) == 0){
        kfree(np->kstack);
        np->kstack = 0;
        np->state = UNUSED;
        pagesCounter--;
        return -1;
    }
    np->sz = curproc->sz;
    np->parent = curproc;
    *np->tf = *curproc->tf;

  // Clear %eax so that fork returns 0 in the child.
  np->tf->eax = 0;

  for(i = 0; i < NOFILE; i++)
    if(curproc->ofile[i])
      np->ofile[i] = filedup(curproc->ofile[i]);
  np->cwd = idup(curproc->cwd);

  safestrcpy(np->name, curproc->name, sizeof(curproc->name));

  pid = np->pid;

  acquire(&ptable.lock);

  np->state = RUNNABLE;

  release(&ptable.lock);

  return pid;
}

// Exit the current process.  Does not return.
// An exited process remains in the zombie state
// until its parent calls wait() to find out it exited.
void
exit(void)
{
  struct proc *curproc = myproc();
  struct proc *p;
  int fd;

  if(curproc == initproc)
    panic("init exiting");

  // Close all open files.
  for(fd = 0; fd < NOFILE; fd++){
    if(curproc->ofile[fd]){
      fileclose(curproc->ofile[fd]);
      curproc->ofile[fd] = 0;
    }
  }

  begin_op();
  iput(curproc->cwd);
  end_op();
  curproc->cwd = 0;

  acquire(&ptable.lock);

  // Parent might be sleeping in wait().
  wakeup1(curproc->parent);

  // Pass abandoned children to init.
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->parent == curproc){
      p->parent = initproc;
      if(p->state == ZOMBIE)
        wakeup1(initproc);
    }
  }

  // Jump into the scheduler, never to return.
  curproc->state = ZOMBIE;
  sched();
  panic("zombie exit");
}

// Wait for a child process to exit and return its pid.
// Return -1 if this process has no children.
int
wait(void)
{
  struct proc *p;
  int havekids, pid, pageIndex;
  struct proc *curproc = myproc();

  acquire(&ptable.lock);
  for(;;){
    // Scan through table looking for exited children.
    havekids = 0;
    for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
      if(p->parent != curproc)
        continue;
      havekids = 1;
      if(p->state == ZOMBIE){
        // Found one.
        pid = p->pid;
        kfree(p->kstack);
        pagesCounter--;
        p->kstack = 0;
        freevm(p->pgdir);
        p->pid = 0;
        p->parent = 0;
        p->name[0] = 0;
        p->killed = 0;
        p->state = UNUSED;
        for (pageIndex = 0; pageIndex < MAX_TOTAL_PAGES - MAX_PSYC_PAGES; pageIndex++) {
                p->diskPages[pageIndex].elements = 0;
        }
        release(&ptable.lock);
        return pid;
      }
    }

    // No point waiting if we don't have any children.
    if(!havekids || curproc->killed){
      release(&ptable.lock);
      return -1;
    }

    // Wait for children to exit.  (See wakeup1 call in proc_exit.)
    sleep(curproc, &ptable.lock);  //DOC: wait-sleep
  }
}

//PAGEBREAK: 42
// Per-CPU process scheduler.
// Each CPU calls scheduler() after setting itself up.
// Scheduler never returns.  It loops, doing:
//  - choose a process to run
//  - swtch to start running that process
//  - eventually that process transfers control
//      via swtch back to the scheduler.
void
scheduler(void)
{
  struct proc *p;
  struct cpu *c = mycpu();
  c->proc = 0;

  for(;;){
    // Enable interrupts on this processor.
    sti();

    // Loop over process table looking for process to run.
    acquire(&ptable.lock);
    for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
      if(p->state != RUNNABLE)
        continue;

      // Switch to chosen process.  It is the process's job
      // to release ptable.lock and then reacquire it
      // before jumping back to us.
      c->proc = p;
      switchuvm(p);
      p->state = RUNNING;

      swtch(&(c->scheduler), p->context);
      switchkvm();

      // Process is done running for now.
      // It should have changed its p->state before coming back.
      c->proc = 0;
    }
    release(&ptable.lock);

  }
}

// Enter scheduler.  Must hold only ptable.lock
// and have changed proc->state. Saves and restores
// intena because intena is a property of this
// kernel thread, not this CPU. It should
// be proc->intena and proc->ncli, but that would
// break in the few places where a lock is held but
// there's no process.
void
sched(void)
{
  int intena;
  struct proc *p = myproc();

  if(!holding(&ptable.lock))
    panic("sched ptable.lock");
  if(mycpu()->ncli != 1)
    panic("sched locks");
  if(p->state == RUNNING)
    panic("sched running");
  if(readeflags()&FL_IF)
    panic("sched interruptible");
  intena = mycpu()->intena;
  swtch(&p->context, mycpu()->scheduler);
  mycpu()->intena = intena;
}

// Give up the CPU for one scheduling round.
void
yield(void)
{
  acquire(&ptable.lock);  //DOC: yieldlock
  myproc()->state = RUNNABLE;
  sched();
  release(&ptable.lock);
}

// A fork child's very first scheduling by scheduler()
// will swtch here.  "Return" to user space.
void
forkret(void)
{
  static int first = 1;
  // Still holding ptable.lock from scheduler.
  release(&ptable.lock);

  if (first) {
    // Some initialization functions must be run in the context
    // of a regular process (e.g., they call sleep), and thus cannot
    // be run from main().
    first = 0;
    iinit(ROOTDEV);
    initlog(ROOTDEV);
  }

  // Return to "caller", actually trapret (see allocproc).
}

// Atomically release lock and sleep on chan.
// Reacquires lock when awakened.
void
sleep(void *chan, struct spinlock *lk)
{
  struct proc *p = myproc();

  if(p == 0)
    panic("sleep");

  if(lk == 0)
    panic("sleep without lk");

  // Must acquire ptable.lock in order to
  // change p->state and then call sched.
  // Once we hold ptable.lock, we can be
  // guaranteed that we won't miss any wakeup
  // (wakeup runs with ptable.lock locked),
  // so it's okay to release lk.
  if(lk != &ptable.lock){  //DOC: sleeplock0
    acquire(&ptable.lock);  //DOC: sleeplock1
    release(lk);
  }
  // Go to sleep.
  p->chan = chan;
  p->state = SLEEPING;

  sched();

  // Tidy up.
  p->chan = 0;

  // Reacquire original lock.
  if(lk != &ptable.lock){  //DOC: sleeplock2
    release(&ptable.lock);
    acquire(lk);
  }
}

//PAGEBREAK!
// Wake up all processes sleeping on chan.
// The ptable lock must be held.
static void
wakeup1(void *chan)
{
  struct proc *p;

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++)
    if(p->state == SLEEPING && p->chan == chan)
      p->state = RUNNABLE;
}

// Wake up all processes sleeping on chan.
void
wakeup(void *chan)
{
  acquire(&ptable.lock);
  wakeup1(chan);
  release(&ptable.lock);
}

// Kill the process with the given pid.
// Process won't exit until it returns
// to user space (see trap in trap.c).
int
kill(int pid)
{
  struct proc *p;

  acquire(&ptable.lock);
  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->pid == pid){
      p->killed = 1;
      // Wake process from sleep if necessary.
      if(p->state == SLEEPING)
        p->state = RUNNABLE;
      release(&ptable.lock);
      return 0;
    }
  }
  release(&ptable.lock);
  return -1;
}

//PAGEBREAK: 36
// Print a process listing to console.  For debugging.
// Runs when user types ^P on console.
// No lock to avoid wedging a stuck machine further.
void
procdump(void)
{
  static char *states[] = {
  [UNUSED]    "unused",
  [EMBRYO]    "embryo",
  [SLEEPING]  "sleep ",
  [RUNNABLE]  "runble",
  [RUNNING]   "run   ",
  [ZOMBIE]    "zombie"
  };
  int i;
  struct proc *p;
  char *state;
  uint pc[10];

  for(p = ptable.proc; p < &ptable.proc[NPROC]; p++){
    if(p->state == UNUSED)
      continue;
    if(p->state >= 0 && p->state < NELEM(states) && states[p->state])
      state = states[p->state];
    else
      state = "???";
    cprintf("%d %s %s", p->pid, state, p->name);
    if(p->state == SLEEPING){
      getcallerpcs((uint*)p->context->ebp+2, pc);
      for(i=0; i<10 && pc[i] != 0; i++)
        cprintf(" %p", pc[i]);
    }
    cprintf("\n");
  }
}


int get_physical_pages() {
  struct proc *curproc = myproc();
  int pagesInRam = 0;
  for (int index = 0; index < curproc->pages.count; ++index){
    if(curproc->pages.location[index] == PHYSICAL)
      pagesInRam++;
  }
  return pagesInRam;
}

int get_page_offset_and_unset_page(uint va) {
  struct proc *curproc = myproc();
  int result = -1;
  // Go over all the disk pages.
  for (int index = 0; index <  MAX_TOTAL_PAGES - MAX_PSYC_PAGES; index++) {
    if (
        curproc->diskPages[index].elements != 0 &&
        curproc->diskPages[index].va == va) {
      curproc->diskPages[index].elements = 0;
      curproc->pages_on_disk--;
      return PGSIZE * index;
    }
  }
  panic("page in disk not found");
  return result;
}

int get_offset_for_page_insert(uint va) {
  struct proc *curproc = myproc();
  for (int index = 0; index <  MAX_TOTAL_PAGES - MAX_PSYC_PAGES; index++) {
    if (!curproc->diskPages[index].elements) {
      // Found an empty disk page.
      curproc->diskPages[index].elements = 1;
      curproc->diskPages[index].va = va;
      curproc->pages_on_disk++;
      curproc->total_pages_on_disk++;
      // Return memory offset to page's start.
      return index * PGSIZE;
    }
  }
  panic("no available page to swap");
  return -1;
}

int addToPages(uint va, struct proc* p) {
  int i,size;
  for (i = 0; i <  MAX_TOTAL_PAGES - MAX_PSYC_PAGES; i++) {
    if(!p->diskPages[i].elements) {
      p->diskPages[i].elements = 1;
      p->diskPages[i].va = va;
      p->pages_on_disk++;
      p->total_pages_on_disk++;
      size = i * PGSIZE;
      return size;
    }
  }
  panic("no pages to swap");
  return -1;
}

/**
 * Find page in current porcess' pages list.
 * @param  uint va
 *  virtual address of the page.
 * @return int index
 *  Index of the page in the pages list, -1 if not found.
 */
int find_page_index(uint va){
  struct proc *curproc = myproc();
  for (int index = 0; index < curproc->pages.count; index++) {
      if(curproc->pages.va[index] == va) {
        return index;
      }
  }
  return -1;
}

void insert_page_va(uint va , memory_location where) {
  struct proc *curproc = myproc();

  int index = find_page_index(va);
  if(index == -1) {
    // Add a new page.
    curproc->pages.count++;
    curproc->pages.va[curproc->pages.count] = va;
  }
  // Add the page to the requested location.
  curproc->pages.location[index] = where;
}

void updateScfifo(int index, uint va, int addition) {
  struct proc *curproc = myproc();

	switch(addition) {
  	case 1:
  		curproc->fifoQueue.va[index] = va;
  		curproc->fifoQueue.elements[index] = addition;
  		curproc->fifoQueue.count++;
  		break;
  	case 0:
  		curproc->fifoQueue.va[index] = addition;
  		curproc->fifoQueue.elements[index] = addition;
  		curproc->fifoQueue.count--;
  		break;
  	default:
  		panic("error");
	}
}

/**
 * Removes a page from the current process' pages array.
 * @param va Virtual address of the page.
 */
void removePage(uint va) {
  struct proc *curproc = myproc();
  int index = find_page_index(va);

  if(index == -1) {
    // Page not found.
    panic("Page not found - cannot remove page");
    return;
  }

  curproc->pages.count--;
  curproc->pages.va[index] = 0;
  curproc->pages.location[index] = BLANK;
  curproc->pages.accesses[index] = 0;
}

/**
 * Find
 */
int findFirstInScfifo(int location, int pred) {
  struct proc *curproc = myproc();

	while (curproc->fifoQueue.elements[location] == pred) {
		location = (location + 1) % MAX_PSYC_PAGES;
	}

	return location;
}

/**
 *
 *
 */
void enqueueScfifo(uint virtual_address) {
  struct proc *curproc = myproc();
	int last = findFirstInScfifo(curproc->fifoQueue.last, 1);
	updateScfifo(last, virtual_address, 1);
	last = (last + 1) % MAX_PSYC_PAGES;
}

uint dequeueScfifo() {
  struct proc *curproc = myproc();
	int first;
	uint va;
	pte_t* page;
	do{
		first = findFirstInScfifo(curproc->fifoQueue.first,0);
		va = curproc->fifoQueue.va[first];
		page = walkpgdir(curproc->pgdir, (void*)va, 0);
		if(PTE_FLAGS(*page) & PTE_A) {
			*page &= ~PTE_A;
			first = (first + 1) % MAX_PSYC_PAGES;
			continue;
		}
		updateScfifo(first, va, 0);
		curproc->fifoQueue.first = (first + 1) % MAX_PSYC_PAGES;
		return va;
	} while(1);
}

void removeElement(uint va) {
	struct proc *curproc = myproc();
	#if SELECTION==SCFIFO
		for(int index = 0; index < MAX_PSYC_PAGES; index++) {
			if(curproc->fifoQueue.va[index] == va) {
				updateScfifo(index, va, 0);
				if(index == curproc->fifoQueue.first) {
					curproc->fifoQueue.first = (curproc->fifoQueue.first + 1) % MAX_PSYC_PAGES;
				}
				if(index == curproc->fifoQueue.last) {
					curproc->fifoQueue.last = (curproc->fifoQueue.last - 1) % MAX_PSYC_PAGES;
				}
				return;
			}
		}
	#else
    // We shouldn't get here if we don't have a relevant scheme.
		panic("no element to remove");
  #endif

}

void updateLap() {
	struct proc *curproc = myproc();
	pte_t* page;
	for(int index = 0; index < MAX_TOTAL_PAGES; index++) {
		if(curproc->pages.location[index] == PHYSICAL) {
			page = walkpgdir(curproc->pgdir, (void*) curproc->pages.va[index], 0);
			if(PTE_FLAGS(*page) & PTE_A) {
				curproc->pages.accesses[index]++;
				*page &= ~PTE_A;
			}
		}
	}
}

uint getLap() {
	struct proc *curproc = myproc();
	int min_access = -1;
	int min_va = 0;
  int index;

	for (index = 0; index < MAX_TOTAL_PAGES; index++) {
		if (curproc->pages.location[index] == PHYSICAL) {
			min_access = curproc->pages.accesses[index];
			min_va = curproc->pages.va[index];
			break;
		}
	}
	if (min_access == -1) panic("no pages in ram");
	for (; index < MAX_TOTAL_PAGES; index++) {
		if (
        curproc->pages.location[index] == PHYSICAL &&
        curproc->pages.accesses[index] < min_access) {
			min_access = curproc->pages.accesses[index];
			min_va = curproc->pages.va[index];
		}
	}
	return min_va;
}
