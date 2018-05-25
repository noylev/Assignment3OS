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

void scRecord(char *va) {
  struct proc *curproc = myproc();
  int i;
  for (i = 0; i < MAX_PSYC_PAGES; i++)
    if (curproc->freepages[i].va == (char*)0xffffffff)
      goto foundrnp;
  cprintf("panic follows, pid:%d, name:%s\n", curproc->pid, curproc->name);
  panic("recordNewPage: no free pages");
foundrnp:

  curproc->freepages[i].va = va;
  curproc->freepages[i].next = curproc->head;
  curproc->freepages[i].prev = 0;
  if(curproc->head != 0)// old head points back to new head
    curproc->head->prev = &curproc->freepages[i];
  else//head == 0 so first link inserted is also the tail
    curproc->tail = &curproc->freepages[i];
  curproc->head = &curproc->freepages[i];
}

void nfuRecord(char *va ){
  struct proc *curproc = myproc();
  int i;

  for (i = 0; i < MAX_PSYC_PAGES; i++)
    if (curproc->freepages[i].va == (char*)0xffffffff)
      goto foundrnp;
  cprintf("panic follows, pid:%d, name:%s\n", curproc->pid, curproc->name);
  panic("recordNewPage: no free pages");
foundrnp:

  curproc->freepages[i].va = va;
}

void recordNewPage(char *va) {
  struct proc *curproc = myproc();

  #if SCFIFO
    scRecord(va);
  #elif NFU
    nfuRecord(va);
  #endif

  curproc->pagesinmem++;
}

struct freepg *fifoWrite() {
  struct proc *curproc = myproc();
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
  lcr3(V2P(curproc->pgdir));
  return l;
}

int check_access_bit(char *va) {
  struct proc *curproc = myproc();
  uint accessed;
  pte_t *pte = walkpgdir(curproc->pgdir, (void*)va, 0);
  if (!*pte)
    panic("check_access_bit: pte1 is empty");
  accessed = (*pte) & PTE_A;
  (*pte) &= ~PTE_A;
  return accessed;
}

struct freepg *scWrite(char *va) {
  struct proc *curproc = myproc();
  int i;
  struct freepg *swapper_page, *original_tail;
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

  swapper_page = curproc->tail;
  original_tail = curproc->tail;// to avoid infinite loop if everyone was accessed
  do{
    //move swapper_page from tail to head
    curproc->tail = curproc->tail->prev;
    curproc->tail->next = 0;
    swapper_page->prev = 0;
    swapper_page->next = curproc->head;
    curproc->head->prev = swapper_page;
    curproc->head = swapper_page;
    swapper_page = curproc->tail;
  }while(check_access_bit(curproc->head->va) && swapper_page != original_tail);


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
  lcr3(V2P(curproc->pgdir));
  curproc->head->va = va;

  // unnecessary but will do for now
  return curproc->head;
}

struct freepg *nfuWrite(char *va) {
  struct proc *curproc = myproc();
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

  lcr3(V2P(curproc->pgdir));
  chosen->va = va;

  // unnecessary but will do for now
  return chosen;
}

struct freepg *writePageToSwapFile(char* va) {

  #if SCFIFO
    return scWrite(va);

  #elif NFU
    return nfuWrite(va);
  #endif

  return 0;
}



// Allocate page tables and physical memory to grow process from oldsz to
// newsz, which need not be page aligned.  Returns new size or 0 on error.
int
allocuvm(pde_t *pgdir, uint oldsz, uint newsz)
{
  #ifndef NONE
    struct proc *curproc = myproc();
  #endif
  char *mem;
  uint a;

#ifndef NONE
  uint newpage = 1;
  struct freepg *l;
#endif

  if(newsz >= KERNBASE)
    return 0;
  if(newsz < oldsz)
    return oldsz;

  a = PGROUNDUP(oldsz);
  // Task 1: on page fault (out of memory), add page.
  for(; a < newsz; a += PGSIZE){
    #ifndef NONE
      if(curproc->pagesinmem >= MAX_PSYC_PAGES) {
        if ((l = writePageToSwapFile((char*)a)) == 0)
          panic("allocuvm: error writing page to swap file");
        newpage = 0;
      }
    #endif
    mem = kalloc();
    if(mem == 0){
      cprintf("allocuvm out of memory\n");
      deallocuvm(pgdir, newsz, oldsz);
      return 0;
    }
 #ifndef NONE
    if (newpage){
      //TODO delete cprintf("nepage = 1");
      //if(proc->pagesinmem >= 11)
        //TODO delete cprintf("recorded new page, proc->name: %s, pagesinmem: %d\n", proc->name, proc->pagesinmem);
      recordNewPage((char*)a);
    }
    #endif

    memset(mem, 0, PGSIZE);
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
  struct proc *curproc = myproc();
  pte_t *pte;
  uint a, pa;
  int i;
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

      if (curproc->pgdir == pgdir) {
        /*
        The process itself is deallocating pages via sbrk() with a negative
        argument. Update proc's data structure accordingly.
        */
#ifndef NONE
        for (i = 0; i < MAX_PSYC_PAGES; i++) {
          if (curproc->freepages[i].va == (char*)a)
            goto founddeallocuvmPTEP;
        }

        panic("deallocuvm: entry not found in proc->freepages");
founddeallocuvmPTEP:
        curproc->freepages[i].va = (char*) 0xffffffff;

#if SCFIFO


        if (curproc->head == &curproc->freepages[i]){
          curproc->head = curproc->freepages[i].next;
          if(curproc->head != 0)
            curproc->head->prev = 0;
          goto doneLooking;
        }
        if (curproc->tail == &curproc->freepages[i]){
          curproc->tail = curproc->freepages[i].prev;
          if(curproc->tail != 0)// should allways be true but lets be extra safe...
            curproc->tail->next = 0;
          goto doneLooking;
        }
        struct freepg *l = curproc->head;
        while (l->next != 0 && l->next != &curproc->freepages[i]){
          l = l->next;
        }
        l->next = curproc->freepages[i].next;
        if (curproc->freepages[i].next != 0){
          curproc->freepages[i].next->prev = l;
        }

doneLooking:
        curproc->freepages[i].next = 0;
        curproc->freepages[i].prev = 0;

#elif NFU
        curproc->freepages[i].age = 0;
#endif
#endif

        curproc->pagesinmem--;
      }
      char *v = P2V(pa);
      kfree(v);
      *pte = 0;
    }
    else if (*pte & PTE_PG && curproc->pgdir == pgdir) {
      /*
      The process itself is deallocating pages via sbrk() with a negative
      argument. Update proc's data structure accordingly.
      */
        for (i = 0; i < MAX_PSYC_PAGES; i++) {
          if (curproc->swappedpages[i].va == (char*)a)
            goto founddeallocuvmPTEPG;
        }
        panic("deallocuvm: entry not found in proc->swappedpages");
founddeallocuvmPTEPG:
        curproc->swappedpages[i].va = (char*) 0xffffffff;
        curproc->swappedpages[i].age = 0;
        curproc->swappedpages[i].swaploc = 0;
        curproc->pagesinswapfile--;
    }


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
     if(!(*pte & PTE_P) && !(*pte & PTE_PG))
      panic("copyuvm: page not present");
    if (*pte & PTE_PG) {
      // cprintf("copyuvm PTR_PG\n"); // TODO delete
      pte = walkpgdir(d, (void*) i, 1);
      *pte = PTE_U | PTE_W | PTE_PG;
      continue;
    }

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

void scfifo_swap(uint addr) {
  struct proc *curproc = myproc();
  int i, j;
  char buf[BUF_SIZE];
  pte_t *pte1, *pte2;
  struct freepg *swapper_page, *original_tail;

  if (curproc->head == 0)
    panic("scfifo_swap: proc->head is NULL");
  if (curproc->head->next == 0)
    panic("scfifo_swap: single page in phys mem");

  swapper_page = curproc->tail;
  // stop condition.
  original_tail = curproc->tail;
  do {
    // Move swapper_page from tail to head.
    curproc->tail = curproc->tail->prev;
    curproc->tail->next = 0;
    swapper_page->prev = 0;
    swapper_page->next = curproc->head;
    curproc->head->prev = swapper_page;
    curproc->head = swapper_page;
    swapper_page = curproc->tail;
  } while(check_access_bit(curproc->head->va) && swapper_page != original_tail);


  // Get address of the page table entry to copy into the swap file
  pte1 = walkpgdir(curproc->pgdir, (void*)curproc->head->va, 0);
  if (!*pte1) {
    panic("swapFile: SCFIFO pte1 is empty");
  }

  // Find a swap file page descriptor slot.
  for (i = 0; i < MAX_PSYC_PAGES; i++){
    if (curproc->swappedpages[i].va == (char*)PTE_ADDR(addr))
      goto foundswappedpageslot;
  }
  panic("scfifo_swap: SCFIFO no slot for swapped page");

foundswappedpageslot:

  curproc->swappedpages[i].va = curproc->head->va;
  //assign the physical page to addr in the relevant page table
  pte2 = walkpgdir(curproc->pgdir, (void*)addr, 0);
  if (!*pte2)
    panic("swapFile: SCFIFO pte2 is empty");
  //set page table entry
  *pte2 = PTE_ADDR(*pte1) | PTE_U | PTE_W | PTE_P;// access bit is zeroed...

  for (j = 0; j < 4; j++) {
    int loc = (i * PGSIZE) + ((PGSIZE / 4) * j);
    int addroffset = ((PGSIZE / 4) * j);
    // int read, written;
    memset(buf, 0, BUF_SIZE);
    //copy the new page from the swap file to buf
    // read =
    readFromSwapFile(curproc, buf, loc, BUF_SIZE);
    //copy the old page from the memory to the swap file
    //written =
    writeToSwapFile(curproc, (char*)(P2V_WO(PTE_ADDR(*pte1)) + addroffset), loc, BUF_SIZE);
    //copy the new page from buf to the memory
    memmove((void*)(PTE_ADDR(addr) + addroffset), (void*)buf, BUF_SIZE);
  }
  //update the page table entry flags, reset the physical page address
  *pte1 = PTE_U | PTE_W | PTE_PG;
  //update l to hold the new va
  //l->next = curproc->head;
  //curproc->head = l;
  curproc->head->va = (char*)PTE_ADDR(addr);

}

void nfuSwap(uint addr) {
  struct proc *curproc = myproc();
  int i, j;

  // MAX_POSSIBLE;
  uint maxIndx = -1, maxAge = 0;
  char buf[BUF_SIZE];
  pte_t *pte1, *pte2;
  struct freepg *chosen;

  for (j = 0; j < MAX_PSYC_PAGES; j++)
    if (curproc->freepages[j].va != (char*)0xffffffff) {
      if (curproc->freepages[j].age > maxAge) {
        maxAge = curproc->freepages[j].age;
        maxIndx = j;
      }
    }

  if(maxIndx == -1)
    panic("nfuSwap: no free page to swap???");
  chosen = &curproc->freepages[maxIndx];

  //find the address of the page table entry to copy into the swap file
  pte1 = walkpgdir(curproc->pgdir, (void*)chosen->va, 0);
  if (!*pte1)
    panic("nfuSwap: pte1 is empty");

//  update accessed bit and age in case it misses a clock tick?
//  be extra careful not to double add by locking
  acquire(&tickslock);
  if((*pte1) & PTE_A){
    ++chosen->age;
    *pte1 &= ~PTE_A;
  }
  release(&tickslock);

  //find a swap file page descriptor slot
  for (i = 0; i < MAX_PSYC_PAGES; i++){
    if (curproc->swappedpages[i].va == (char*)PTE_ADDR(addr))
      goto foundswappedpageslot;
  }
  panic("nfuSwap: no slot for swapped page");

foundswappedpageslot:

  curproc->swappedpages[i].va = chosen->va;
  //assign the physical page to addr in the relevant page table
  pte2 = walkpgdir(curproc->pgdir, (void*)addr, 0);
  if (!*pte2)
    panic("nfuSwap: pte2 is empty");
  //set page table entry

  *pte2 = PTE_ADDR(*pte1) | PTE_U | PTE_W | PTE_P;// access bit is zeroed...

  for (j = 0; j < 4; j++) {
    int loc = (i * PGSIZE) + ((PGSIZE / 4) * j);

    int addroffset = ((PGSIZE / 4) * j);
    // int read, written;
    memset(buf, 0, BUF_SIZE);
    //copy the new page from the swap file to buf
    // read =
    readFromSwapFile(curproc, buf, loc, BUF_SIZE);

    //copy the old page from the memory to the swap file
    //written =
    writeToSwapFile(curproc, (char*)(P2V_WO(PTE_ADDR(*pte1)) + addroffset), loc, BUF_SIZE);

    //copy the new page from buf to the memory
    memmove((void*)(PTE_ADDR(addr) + addroffset), (void*)buf, BUF_SIZE);
  }
  //update the page table entry flags, reset the physical page address
  *pte1 = PTE_U | PTE_W | PTE_PG;
  //update l to hold the new va
  //l->next = curproc->head;
  //curproc->head = l;
  chosen->va = (char*)PTE_ADDR(addr);
  // was this missed some how???
  chosen->age = 0;
}

void swap_page(uint addr) {
  struct proc *curproc = myproc();

  if (strcmp(curproc->name, "init") == 0 || strcmp(curproc->name, "sh") == 0) {
    curproc->pagesinmem++;
    return;
  }

#if SCFIFO
  scfifo_swap(addr);
#elif NFU
  nfuSwap(addr);
#endif

  lcr3(V2P(curproc->pgdir));
  ++curproc->totalPagedOutCount;
}






/* TTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTTT

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
*/
//PAGEBREAK!
// Blank page.
//PAGEBREAK!
// Blank page.
//PAGEBREAK!
// Blank page.
