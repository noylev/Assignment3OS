#include "param.h"
#include "types.h"
#include "defs.h"
#include "x86.h"
#include "memlayout.h"
#include "mmu.h"
#include "proc.h"
#include "elf.h"
#define BUF_SIZE PGSIZE/4
#define MAX_POSSIBLE ~0x80000000
#define ADD_TO_AGE 0x40000000
#define DEBUG 0

int strcmp(const char *p, const char *q) { 
  int answer;
  while(*p && *p == *q){
    p++;
    q++;
  }
  answer = (uchar)*p - (uchar)*q;
  return answer;
}


extern char data[];  // defined by kernel.ld
pde_t *kpgdir;  // for use in scheduler()
int deallocCount = 0;
// Set up CPU's kernel segment descriptors.
// Run once on entry on each CPU.
void
seginit(void)
{
  struct cpu *c;

  // Map "logical" addresses to virtual addresses using identity map.
  // Cannot share a CODE descriptor for both kernel and user
  // because it would have to have DPL_USR, but the CPU forbids
  // an interrupt from CPL=0 to DPL=3.
  c = &cpus[cpuid()];
  c->gdt[SEG_KCODE] = SEG(STA_X|STA_R, 0, 0xffffffff, 0);
  c->gdt[SEG_KDATA] = SEG(STA_W, 0, 0xffffffff, 0);
  c->gdt[SEG_UCODE] = SEG(STA_X|STA_R, 0, 0xffffffff, DPL_USER);
  c->gdt[SEG_UDATA] = SEG(STA_W, 0, 0xffffffff, DPL_USER);
  lgdt(c->gdt, sizeof(c->gdt));
}

// Return the address of the PTE in page table pgdir
// that corresponds to virtual address va.  If alloc!=0,
// create any required page table pages.
pte_t *walkpgdir(pde_t *pgdir, const void *va, int alloc){ //noy : I removed the static in the signature
  pde_t *pde;
  pte_t *pgtab;

  pde = &pgdir[PDX(va)];
  if(*pde & PTE_P){
    pgtab = (pte_t*)P2V(PTE_ADDR(*pde));
  } else {
    if(!alloc || (pgtab = (pte_t*)kalloc()) == 0)
      return 0;
    pagesCounter++; //added by noy

    // Make sure all those PTE_P bits are zero.
    memset(pgtab, 0, PGSIZE);
    // The permissions here are overly generous, but they can
    // be further restricted by the permissions in the page table
    // entries, if necessary.
    *pde = V2P(pgtab) | PTE_P | PTE_W | PTE_U;
  }
  return &pgtab[PTX(va)];
}

// Create PTEs for virtual addresses starting at va that refer to
// physical addresses starting at pa. va and size might not
// be page-aligned.
static int
mappages(pde_t *pgdir, void *va, uint size, uint pa, int perm)
{
  char *a, *last;
  pte_t *pte;

  a = (char*)PGROUNDDOWN((uint)va);
  last = (char*)PGROUNDDOWN(((uint)va) + size - 1);
  for(;;){
    if((pte = walkpgdir(pgdir, a, 1)) == 0)
      return -1;
    if(*pte & PTE_P)
      panic("remap");
    *pte = pa | perm | PTE_P;
    if(a == last)
      break;
    a += PGSIZE;
    pa += PGSIZE;
  }
  return 0;
}

// There is one page table per process, plus one that's used when
// a CPU is not running any process (kpgdir). The kernel uses the
// current process's page table during system calls and interrupts;
// page protection bits prevent user code from using the kernel's
// mappings.
//
// setupkvm() and exec() set up every page table like this:
//
//   0..KERNBASE: user memory (text+data+stack+heap), mapped to
//                phys memory allocated by the kernel
//   KERNBASE..KERNBASE+EXTMEM: mapped to 0..EXTMEM (for I/O space)
//   KERNBASE+EXTMEM..data: mapped to EXTMEM..V2P(data)
//                for the kernel's instructions and r/o data
//   data..KERNBASE+PHYSTOP: mapped to V2P(data)..PHYSTOP,
//                                  rw data + free physical memory
//   0xfe000000..0: mapped direct (devices such as ioapic)
//
// The kernel allocates physical memory for its heap and for user memory
// between V2P(end) and the end of physical memory (PHYSTOP)
// (directly addressable from end..P2V(PHYSTOP)).

// This table defines the kernel's mappings, which are present in
// every process's page table.
static struct kmap {
  void *virt;
  uint phys_start;
  uint phys_end;
  int perm;
} kmap[] = {
 { (void*)KERNBASE, 0,             EXTMEM,    PTE_W}, // I/O space
 { (void*)KERNLINK, V2P(KERNLINK), V2P(data), 0},     // kern text+rodata
 { (void*)data,     V2P(data),     PHYSTOP,   PTE_W}, // kern data+memory
 { (void*)DEVSPACE, DEVSPACE,      0,         PTE_W}, // more devices
};

// Set up kernel part of a page table.
pde_t*
setupkvm(void)
{
  pde_t *pgdir;
  struct kmap *k;

  if((pgdir = (pde_t*)kalloc()) == 0)
    return 0;
  pagesCounter++; // added by noy
  memset(pgdir, 0, PGSIZE);
  if (P2V(PHYSTOP) > (void*)DEVSPACE)
    panic("PHYSTOP too high");
  for(k = kmap; k < &kmap[NELEM(kmap)]; k++)
    if(mappages(pgdir, k->virt, k->phys_end - k->phys_start,
                (uint)k->phys_start, k->perm) < 0) {
      freevm(pgdir);
      return 0;
    }
  return pgdir;
}

// Allocate one page table for the machine for the kernel address
// space for scheduler processes.
void
kvmalloc(void)
{
  kpgdir = setupkvm();
  switchkvm();
}

// Switch h/w page table register to the kernel-only page table,
// for when no process is running.
void
switchkvm(void)
{
  lcr3(V2P(kpgdir));   // switch to the kernel page table
}

// Switch TSS and h/w page table to correspond to process p.
void
switchuvm(struct proc *p)
{
  if(p == 0)
    panic("switchuvm: no process");
  if(p->kstack == 0)
    panic("switchuvm: no kstack");
  if(p->pgdir == 0)
    panic("switchuvm: no pgdir");

  pushcli();
  mycpu()->gdt[SEG_TSS] = SEG16(STS_T32A, &mycpu()->ts,
                                sizeof(mycpu()->ts)-1, 0);
  mycpu()->gdt[SEG_TSS].s = 0;
  mycpu()->ts.ss0 = SEG_KDATA << 3;
  mycpu()->ts.esp0 = (uint)p->kstack + KSTACKSIZE;
  // setting IOPL=0 in eflags *and* iomb beyond the tss segment limit
  // forbids I/O instructions (e.g., inb and outb) from user space
  mycpu()->ts.iomb = (ushort) 0xFFFF;
  ltr(SEG_TSS << 3);
  lcr3(V2P(p->pgdir));  // switch to process's address space
  popcli();
}

// Load the initcode into address 0 of pgdir.
// sz must be less than a page.
void
inituvm(pde_t *pgdir, char *init, uint sz)
{
  char *mem;

  if(sz >= PGSIZE)
    panic("inituvm: more than a page");
  mem = kalloc();
  pagesCounter++; // added by noy
  memset(mem, 0, PGSIZE);
  mappages(pgdir, 0, PGSIZE, V2P(mem), PTE_W|PTE_U);
  memmove(mem, init, sz);
}

// Load a program segment into pgdir.  addr must be page-aligned
// and the pages from addr to addr+sz must already be mapped.
int
loaduvm(pde_t *pgdir, char *addr, struct inode *ip, uint offset, uint sz)
{
  uint i, pa, n;
  pte_t *pte;

  if((uint) addr % PGSIZE != 0)
    panic("loaduvm: addr must be page aligned");
  for(i = 0; i < sz; i += PGSIZE){
    if((pte = walkpgdir(pgdir, addr+i, 0)) == 0)
      panic("loaduvm: address should exist");
    pa = PTE_ADDR(*pte);
    if(sz - i < PGSIZE)
      n = sz - i;
    else
      n = PGSIZE;
    if(readi(ip, P2V(pa), offset+i, n) != n)
      return -1;
  }
  return 0;
}

void scRecord(char *va){
  int i;
  //TODO delete cprintf("scRecord!\n");
  for (i = 0; i < MAX_PSYC_PAGES; i++)
    if (proc->freepages[i].va == (char*)0xffffffff)
      goto foundrnp;
  cprintf("panic follows, pid:%d, name:%s\n", proc->pid, proc->name);
  panic("recordNewPage: no free pages");
foundrnp:
  //TODO delete cprintf("found unused page!\n");
  proc->freepages[i].va = va;
  proc->freepages[i].next = proc->head;
  proc->freepages[i].prev = 0;
  if(proc->head != 0)// old head points back to new head
    proc->head->prev = &proc->freepages[i];
  else//head == 0 so first link inserted is also the tail
    proc->tail = &proc->freepages[i];
  proc->head = &proc->freepages[i];
}

void nfuRecord(char *va){
  int i;
  
  for (i = 0; i < MAX_PSYC_PAGES; i++)
    if (proc->freepages[i].va == (char*)0xffffffff)
      goto foundrnp;
  cprintf("panic follows, pid:%d, name:%s\n", proc->pid, proc->name);
  panic("recordNewPage: no free pages");
foundrnp:
 
  proc->freepages[i].va = va;
}

void recordNewPage(char *va) { 

#if SCFIFO  
  scRecord(va);
#else

#if NFU
  nfuRecord(va);
#endif
#endif

  curproc->pagesinmem++;
}

struct freepg *fifoWrite() {
  int i;
  struct freepg *link, *l;
  for (i = 0; i < MAX_PSYC_PAGES; i++){
    if (curproc->swappedpages[i].va == (char*)0xffffffff)
      goto foundswappedpageslot;
  }
  panic("writePageToSwapFile: FIFO no slot for swapped page");
foundswappedpageslot:
  link = curproc->head;
  if (link == 0)
    panic("fifoWrite: curproc->head is NULL");
  if (link->next == 0)
    panic("fifoWrite: single page in phys mem");
  // find the before-last link in the used pages list
  while (link->next->next != 0)
    link = link->next;
  l = link->next;
  link->next = 0;


  curproc->swappedpages[i].va = l->va;
  int num = 0;
  if ((num = writeToSwapFile(curproc, (char*)PTE_ADDR(l->va), i * PGSIZE, PGSIZE)) == 0)
    return 0; 
  pte_t *pte1 = walkpgdir(curproc->pgdir, (void*)l->va, 0);
  if (!*pte1)
    panic("writePageToSwapFile: pte1 is empty"); 
  kfree((char*)PTE_ADDR(P2V_WO(*walkpgdir(curproc->pgdir, l->va, 0))));
  *pte1 = PTE_W | PTE_U | PTE_PG;
  ++curproc->totalPagedOutCount;
  ++curproc->pagesinswapfile;
  lcr3(v2p(curproc->pgdir));
  return l;
}

int checkAccBit(char *va){
  uint accessed;
  pte_t *pte = walkpgdir(curproc->pgdir, (void*)va, 0);
  if (!*pte)
    panic("checkAccBit: pte1 is empty");
  accessed = (*pte) & PTE_A;
  (*pte) &= ~PTE_A;
  return accessed;
}

struct freepg *scWrite(char *va) {  
  int i;
  struct freepg *mover, *oldTail;
  for (i = 0; i < MAX_PSYC_PAGES; i++){
    if (curproc->swappedpages[i].va == (char*)0xffffffff)
      goto foundswappedpageslot;
  }
  panic("writePageToSwapFile: FIFO no slot for swapped page");

foundswappedpageslot:
    //link = curproc->head;
  if (curproc->head == 0)
    panic("scWrite: curproc->head is NULL");
  if (curproc->head->next == 0)
    panic("scWrite: single page in phys mem");

  mover = curproc->tail;
  oldTail = curproc->tail;// to avoid infinite loop if everyone was accessed
  do{
    //move mover from tail to head
    curproc->tail = curproc->tail->prev;
    curproc->tail->next = 0;
    mover->prev = 0;
    mover->next = curproc->head;
    curproc->head->prev = mover;
    curproc->head = mover;
    mover = curproc->tail;
  }while(checkAccBit(curproc->head->va) && mover != oldTail);

  if(DEBUG){   
    cprintf("SCFIFO chose to page out page starting at 0x%x \n\n", curproc->head->va);
  }

  //make the swap
  curproc->swappedpages[i].va = curproc->head->va;
  int num = 0;
  if ((num = writeToSwapFile(curproc, (char*)PTE_ADDR(curproc->head->va), i * PGSIZE, PGSIZE)) == 0)
    return 0;

  pte_t *pte1 = walkpgdir(curproc->pgdir, (void*)curproc->head->va, 0);
  if (!*pte1)
    panic("writePageToSwapFile: pte1 is empty");

  kfree((char*)PTE_ADDR(P2V_WO(*walkpgdir(curproc->pgdir, curproc->head->va, 0))));
  *pte1 = PTE_W | PTE_U | PTE_PG;
  ++curproc->totalPagedOutCount;
  ++curproc->pagesinswapfile;
  lcr3(v2p(curproc->pgdir));
  curproc->head->va = va;

  // unnecessary but will do for now
  return curproc->head;
}

struct freepg *nfuWrite(char *va) {
  int i, j;
  uint maxIndx = -1, maxAge = 0; //MAX_POSSIBLE;
  struct freepg *chosen;

  for (i = 0; i < MAX_PSYC_PAGES; i++){
    if (curproc->swappedpages[i].va == (char*)0xffffffff)
      goto foundswappedpageslot;
  }
  panic("writePageToSwapFile: FIFO no slot for swapped page");

foundswappedpageslot:
  for (j = 0; j < MAX_PSYC_PAGES; j++)
    if (curproc->freepages[j].va != (char*)0xffffffff){      
      if (curproc->freepages[j].age > maxAge){
        maxAge = curproc->freepages[j].age;
        maxIndx = j;
      }     
    }

  if(maxIndx == -1)
    panic("nfuWrite: no free page to swap???");
  chosen = &curproc->freepages[maxIndx];

  if(DEBUG){    
    cprintf("NFU chose to page out page starting at 0x%x \n\n", chosen->va);
  }

  pte_t *pte1 = walkpgdir(curproc->pgdir, (void*)chosen->va, 0);
  if (!*pte1)
    panic("writePageToSwapFile: pte1 is empty");
  acquire(&tickslock);
 
  if((*pte1) & PTE_A){
    ++chosen->age;
    *pte1 &= ~PTE_A;
    
  }
  release(&tickslock);

  //make swap
  curproc->swappedpages[i].va = chosen->va;
  int num = 0;
  if ((num = writeToSwapFile(curproc, (char*)PTE_ADDR(chosen->va), i * PGSIZE, PGSIZE)) == 0)
    return 0;

  kfree((char*)PTE_ADDR(P2V_WO(*walkpgdir(curproc->pgdir, chosen->va, 0))));
  *pte1 = PTE_W | PTE_U | PTE_PG;
  ++curproc->totalPagedOutCount;
  ++curproc->pagesinswapfile;
  
  lcr3(v2p(curproc->pgdir));
  chosen->va = va;

  // unnecessary but will do for now
  return chosen;
}

struct freepg *writePageToSwapFile(char* va) {

#if SCFIFO  
  return scWrite(va);
#else

#if NFU
  return nfuWrite(va);
#endif
#endif 
  return 0;
}



// Allocate page tables and physical memory to grow process from oldsz to
// newsz, which need not be page aligned.  Returns new size or 0 on error.
int
allocuvm(pde_t *pgdir, uint oldsz, uint newsz)
{
  struct proc *curproc = myproc();
  char *mem;
  uint a;

  if(newsz >= KERNBASE)
    return 0;
  if(newsz < oldsz)
    return oldsz;

  a = PGROUNDUP(oldsz);
  // Task 1: on page fault (out of memory), add page.
  for(; a < newsz; a += PGSIZE){
    if(get_physical_pages() >= MAX_PSYC_PAGES && SELECTION != NONE ) {
      // Too many physical pages.
      swap_page();
    }
    mem = kalloc();
    if(mem == 0){
      cprintf("allocuvm out of memory\n");
      deallocuvm(pgdir, newsz, oldsz);
      return 0;
    }

    pagesCounter++;
    memset(mem, 0, PGSIZE);
    // Task 2: override "out of memory" with write-to-disk.
    if((strcmp(curproc->name, "sh") != 0) && (strcmp(curproc->name, "init") != 0)){
      #if SELECTION==SCFIFO
        enqueueScfifo(a);
      #endif
      #if SELECTION==AQ
        add_aq_node(a);
      #endif
    }
    insert_page_va(a, PHYSICAL);
    mappages(pgdir, (char*)a, PGSIZE, V2P(mem), PTE_W|PTE_U);
  }

  return newsz;
}

// Deallocate user pages to bring the process size from oldsz to
// newsz.  oldsz and newsz need not be page-aligned, nor does newsz
// need to be less than oldsz.  oldsz can be larger than the actual
// process size.  Returns the new process size.
int
deallocuvm(pde_t *pgdir, uint oldsz, uint newsz)
{
  pte_t *pte;
  uint a, pa;

  if(newsz >= oldsz)
    return oldsz;

  a = PGROUNDUP(newsz);
  for(; a  < oldsz; a += PGSIZE){
    pte = walkpgdir(pgdir, (char*)a, 0);
    if(!pte)
      a = PGADDR(PDX(a) + 1, 0, 0) - PGSIZE;
    else if((*pte & PTE_P) != 0){
      pa = PTE_ADDR(*pte);
      if(pa == 0)
        panic("kfree");
      char *v = P2V(pa);
      kfree(v);
      *pte = 0;
    }
  }
  return newsz;
}


// TASK 1 - new allocuvm
int
NewDeallocuvm(pde_t *pgdir, uint oldsz, uint newsz)
{
  pte_t *pte;
  uint a, pa;

  if(newsz >= oldsz)
    return oldsz;

  a = PGROUNDUP(newsz);
  for(; a  < oldsz; a += PGSIZE){
    pte = walkpgdir(pgdir, (char*)a, 0);
    if(!pte)
      a += (NPTENTRIES - 1) * PGSIZE;
     else if((*pte & PTE_P) != 0){
        pa = PTE_ADDR(*pte);
        if(pa == 0)
          panic("kfree");
        char *v = P2V(pa);
        kfree(v);
        pagesCounter--;
        *pte = 0;
    }
    else {
        get_page_offset_and_unset_page(a);
    }
    removePage(a);
    removeElement(a);
  }
  return newsz;
}


// Free a page table and all the physical memory pages
// in the user part.
void
freevm(pde_t *pgdir)
{
  uint i;

  if(pgdir == 0)
    panic("freevm: no pgdir");
  deallocuvm(pgdir, KERNBASE, 0);
  for(i = 0; i < NPDENTRIES; i++){
    if(pgdir[i] & PTE_P){
      char * v = P2V(PTE_ADDR(pgdir[i]));
      kfree(v);
    }
  }
  kfree((char*)pgdir);
}

// Clear PTE_U on a page. Used to create an inaccessible
// page beneath the user stack.
void
clearpteu(pde_t *pgdir, char *uva)
{
  pte_t *pte;

  pte = walkpgdir(pgdir, uva, 0);
  if(pte == 0)
    panic("clearpteu");
  *pte &= ~PTE_U;
}

// Given a parent process's page table, create a copy
// of it for a child.
pde_t*
copyuvm(pde_t *pgdir, uint sz)
{
  pde_t *d;
  pte_t *pte;
  uint pa, i, flags;
  char *mem;

  if((d = setupkvm()) == 0)
    return 0;
  for(i = 0; i < sz; i += PGSIZE){
    if((pte = walkpgdir(pgdir, (void *) i, 0)) == 0)
      panic("copyuvm: pte should exist");
    if(!(*pte & PTE_P))
      panic("copyuvm: page not present");
    pa = PTE_ADDR(*pte);
    flags = PTE_FLAGS(*pte);
    if((mem = kalloc()) == 0)
      goto bad;
    memmove(mem, (char*)P2V(pa), PGSIZE);
    if(mappages(d, (void*)i, PGSIZE, V2P(mem), flags) < 0)
      goto bad;
  }
  return d;

bad:
  freevm(d);
  return 0;
}

//PAGEBREAK!
// Map user virtual address to kernel address.
char*
uva2ka(pde_t *pgdir, char *uva)
{
  pte_t *pte;

  pte = walkpgdir(pgdir, uva, 0);
  if((*pte & PTE_P) == 0)
    return 0;
  if((*pte & PTE_U) == 0)
    return 0;
  return (char*)P2V(PTE_ADDR(*pte));
}

// Copy len bytes from p to user address va in page table pgdir.
// Most useful when pgdir is not the current page table.
// uva2ka ensures this only works for PTE_U pages.
int
copyout(pde_t *pgdir, uint va, void *p, uint len)
{
  char *buf, *pa0;
  uint n, va0;

  buf = (char*)p;
  while(len > 0){
    va0 = (uint)PGROUNDDOWN(va);
    pa0 = uva2ka(pgdir, (char*)va0);
    if(pa0 == 0)
      return -1;
    n = PGSIZE - (va - va0);
    if(n > len)
      n = len;
    memmove(pa0 + (va - va0), buf, n);
    len -= n;
    buf += n;
    va = va0 + PGSIZE;
  }
  return 0;
}

/**
 * Gets the next virtual address (according to the selection scheme).
 */
uint get_va() {
  #if SELECTION==SCFIFO
      return dequeueScfifo();
  #endif
  #if SELECTION==LAPA
      return getLap();
  #endif
  #if SELECTION==NFUA
      return get_nfua_page_to_swap();
  #endif

  // Error.
  return -1;
}

void swap_page() {
  struct proc *curproc = myproc();
  uint va = get_va();

  // Get the PTE of the virtual address.
  pte_t* pte = walkpgdir(curproc->pgdir, (void*) va, 0);
  // Get physical address of page's actual data.
  uint addr = (uint) P2V(PTE_ADDR(*pte));
  int offset = get_offset_for_page_insert(va);
  insert_page_va(va, DISK);
  // Set paged out to secondary storage flag.
  *pte |= PTE_PG;
  // Page no longer present & not user-controlled.
  *pte &= ~PTE_P;
  *pte &= ~PTE_U;

  // Write the page to the swap file.
  if(writeToSwapFile(curproc, (char*)addr, offset, PGSIZE) == -1) {
      panic("can't write to swap file");
  }

  // Remove page from physical memory.
  kfree((char*) addr);
  pagesCounter--;

  // Clear that pesky flag.
  lcr3(V2P(curproc->pgdir));
}

void update_access_counters(struct proc *process) {
  uint page_accesses;
  pte_t* pte;
  int bit_comparer = 1;
  for (int index = 0; index < MAX_PSYC_PAGES; index++) {

    page_accesses = process->pages.accesses[index];
    pte = walkpgdir(process->pgdir, (void *) process->diskPages[index].va, 0);
    page_accesses >>= 1;
    if (*pte & PTE_A){
      page_accesses |= (bit_comparer << 31);
      *pte &= ~PTE_A;
    }
    process->pages.accesses[index] = page_accesses;
  }

  return;
}

//PAGEBREAK!
// Blank page.
//PAGEBREAK!
// Blank page.
//PAGEBREAK!
// Blank page.
