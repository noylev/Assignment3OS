
_myMemTest:     file format elf32-i386


Disassembly of section .text:

00000000 <main>:
#define PGSIZE 4096
#define FREE_SPACE_ON_RAM 12
void waitForUserToAnalyze();


int main(int argc, char *argv[]){
   0:	8d 4c 24 04          	lea    0x4(%esp),%ecx
   4:	83 e4 f0             	and    $0xfffffff0,%esp
   7:	ff 71 fc             	pushl  -0x4(%ecx)
   a:	55                   	push   %ebp
   b:	89 e5                	mov    %esp,%ebp
   d:	57                   	push   %edi
   e:	56                   	push   %esi
   f:	53                   	push   %ebx
  10:	51                   	push   %ecx
    
    //allocate 12 pages
    char* pages[25];
    int i;
    printf(1,"Allocating 12 pages (0-11)..\n");
    for(i=0; i < FREE_SPACE_ON_RAM; ++i){
  11:	31 db                	xor    %ebx,%ebx
#define PGSIZE 4096
#define FREE_SPACE_ON_RAM 12
void waitForUserToAnalyze();


int main(int argc, char *argv[]){
  13:	81 ec 90 00 00 00    	sub    $0x90,%esp
	#endif
    
    //allocate 12 pages
    char* pages[25];
    int i;
    printf(1,"Allocating 12 pages (0-11)..\n");
  19:	68 2c 0a 00 00       	push   $0xa2c
  1e:	6a 01                	push   $0x1
  20:	e8 ab 05 00 00       	call   5d0 <printf>
  25:	83 c4 10             	add    $0x10,%esp
  28:	90                   	nop
  29:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
    for(i=0; i < FREE_SPACE_ON_RAM; ++i){
        pages[i] = sbrk(PGSIZE);
  30:	83 ec 0c             	sub    $0xc,%esp
  33:	68 00 10 00 00       	push   $0x1000
  38:	e8 cd 04 00 00       	call   50a <sbrk>
        printf(1, "page #%d at address: %x\n", i, pages[i]);
  3d:	50                   	push   %eax
  3e:	53                   	push   %ebx
  3f:	68 4a 0a 00 00       	push   $0xa4a
  44:	6a 01                	push   $0x1
    //allocate 12 pages
    char* pages[25];
    int i;
    printf(1,"Allocating 12 pages (0-11)..\n");
    for(i=0; i < FREE_SPACE_ON_RAM; ++i){
        pages[i] = sbrk(PGSIZE);
  46:	89 44 9d 84          	mov    %eax,-0x7c(%ebp,%ebx,4)
    
    //allocate 12 pages
    char* pages[25];
    int i;
    printf(1,"Allocating 12 pages (0-11)..\n");
    for(i=0; i < FREE_SPACE_ON_RAM; ++i){
  4a:	83 c3 01             	add    $0x1,%ebx
        pages[i] = sbrk(PGSIZE);
        printf(1, "page #%d at address: %x\n", i, pages[i]);
  4d:	e8 7e 05 00 00       	call   5d0 <printf>
    
    //allocate 12 pages
    char* pages[25];
    int i;
    printf(1,"Allocating 12 pages (0-11)..\n");
    for(i=0; i < FREE_SPACE_ON_RAM; ++i){
  52:	83 c4 20             	add    $0x20,%esp
  55:	83 fb 0c             	cmp    $0xc,%ebx
  58:	75 d6                	jne    30 <main+0x30>
        pages[i] = sbrk(PGSIZE);
        printf(1, "page #%d at address: %x\n", i, pages[i]);
    }
    printf(1,"Reached max. number of pages on RAM..\n"); //i=11
  5a:	83 ec 08             	sub    $0x8,%esp
  5d:	68 24 09 00 00       	push   $0x924
  62:	6a 01                	push   $0x1
  64:	e8 67 05 00 00       	call   5d0 <printf>
    waitForUserToAnalyze();
  69:	e8 a2 01 00 00       	call   210 <waitForUserToAnalyze>
    
    //access pages
    printf(1,"Accessing pages 0-2\n");
  6e:	59                   	pop    %ecx
  6f:	5e                   	pop    %esi
  70:	68 63 0a 00 00       	push   $0xa63
  75:	6a 01                	push   $0x1
  77:	e8 54 05 00 00       	call   5d0 <printf>
    pages[0][0]=1;
  7c:	8b 45 84             	mov    -0x7c(%ebp),%eax
  7f:	c6 00 01             	movb   $0x1,(%eax)
    pages[1][0]=1;
  82:	8b 45 88             	mov    -0x78(%ebp),%eax
  85:	c6 00 01             	movb   $0x1,(%eax)
    pages[2][0]=1;
  88:	8b 45 8c             	mov    -0x74(%ebp),%eax
  8b:	c6 00 01             	movb   $0x1,(%eax)
    printf(1,"All pages on RAM, no page faults expected.\n");
  8e:	5f                   	pop    %edi
  8f:	58                   	pop    %eax
  90:	68 4c 09 00 00       	push   $0x94c
  95:	6a 01                	push   $0x1
  97:	e8 34 05 00 00       	call   5d0 <printf>
    waitForUserToAnalyze();
  9c:	e8 6f 01 00 00       	call   210 <waitForUserToAnalyze>
    
    //allocate 12 more pages
    printf(1,"Allocating 12 more pages (12 swap outs should occur).\n"); //i=22
  a1:	58                   	pop    %eax
  a2:	5a                   	pop    %edx
  a3:	68 78 09 00 00       	push   $0x978
  a8:	6a 01                	push   $0x1
  aa:	e8 21 05 00 00       	call   5d0 <printf>
  af:	83 c4 10             	add    $0x10,%esp
  b2:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
    int j;
    for(j=0; j<FREE_SPACE_ON_RAM; j++){
    	printf(1, "page #%d at address: %x\n", i, pages[i]);
  b8:	ff 74 9d 84          	pushl  -0x7c(%ebp,%ebx,4)
  bc:	53                   	push   %ebx
  bd:	68 4a 0a 00 00       	push   $0xa4a
  c2:	6a 01                	push   $0x1
  c4:	e8 07 05 00 00       	call   5d0 <printf>
        pages[i] = sbrk(PGSIZE);
  c9:	c7 04 24 00 10 00 00 	movl   $0x1000,(%esp)
  d0:	e8 35 04 00 00       	call   50a <sbrk>
  d5:	89 44 9d 84          	mov    %eax,-0x7c(%ebp,%ebx,4)
        
        i++;
  d9:	83 c3 01             	add    $0x1,%ebx
    waitForUserToAnalyze();
    
    //allocate 12 more pages
    printf(1,"Allocating 12 more pages (12 swap outs should occur).\n"); //i=22
    int j;
    for(j=0; j<FREE_SPACE_ON_RAM; j++){
  dc:	83 c4 10             	add    $0x10,%esp
  df:	83 fb 18             	cmp    $0x18,%ebx
  e2:	75 d4                	jne    b8 <main+0xb8>
    }

    // LIFO:	swap only the last page, 15 ||| 1-14 remains
    // SCFIFO:	swap pages 6-15,3-4 ||| 1,2,5 remains
    // LAP:		swap pages 6-15 (6&7 twice) ||| 1-5 remains
    waitForUserToAnalyze();
  e4:	e8 27 01 00 00       	call   210 <waitForUserToAnalyze>

    printf(1,"Accessing pages 0,1,2,5,14\n");
  e9:	83 ec 08             	sub    $0x8,%esp
  ec:	68 78 0a 00 00       	push   $0xa78
  f1:	6a 01                	push   $0x1
  f3:	e8 d8 04 00 00       	call   5d0 <printf>
    pages[0][0]=1;
    pages[1][0]=1;
    pages[2][0]=1;
    pages[5][0]=1;
  f8:	8b 45 98             	mov    -0x68(%ebp),%eax
    // SCFIFO:	swap pages 6-15,3-4 ||| 1,2,5 remains
    // LAP:		swap pages 6-15 (6&7 twice) ||| 1-5 remains
    waitForUserToAnalyze();

    printf(1,"Accessing pages 0,1,2,5,14\n");
    pages[0][0]=1;
  fb:	8b 7d 84             	mov    -0x7c(%ebp),%edi
    pages[1][0]=1;
  fe:	8b 75 88             	mov    -0x78(%ebp),%esi
    pages[2][0]=1;
 101:	8b 5d 8c             	mov    -0x74(%ebp),%ebx
    // SCFIFO:	swap pages 6-15,3-4 ||| 1,2,5 remains
    // LAP:		swap pages 6-15 (6&7 twice) ||| 1-5 remains
    waitForUserToAnalyze();

    printf(1,"Accessing pages 0,1,2,5,14\n");
    pages[0][0]=1;
 104:	c6 07 01             	movb   $0x1,(%edi)
    pages[1][0]=1;
    pages[2][0]=1;
    pages[5][0]=1;
 107:	89 85 74 ff ff ff    	mov    %eax,-0x8c(%ebp)
    // LAP:		swap pages 6-15 (6&7 twice) ||| 1-5 remains
    waitForUserToAnalyze();

    printf(1,"Accessing pages 0,1,2,5,14\n");
    pages[0][0]=1;
    pages[1][0]=1;
 10d:	c6 06 01             	movb   $0x1,(%esi)
    pages[2][0]=1;
 110:	c6 03 01             	movb   $0x1,(%ebx)
    pages[5][0]=1;
 113:	c6 00 01             	movb   $0x1,(%eax)
    pages[14][0]=1;
 116:	8b 45 bc             	mov    -0x44(%ebp),%eax
 119:	c6 00 01             	movb   $0x1,(%eax)
 11c:	89 85 70 ff ff ff    	mov    %eax,-0x90(%ebp)
    printf(1,"Expected page faults:\n[LIFO-1] [SCFIFO-3] [LAP-2]\n");
 122:	59                   	pop    %ecx
 123:	58                   	pop    %eax
 124:	68 b0 09 00 00       	push   $0x9b0
 129:	6a 01                	push   $0x1
 12b:	e8 a0 04 00 00       	call   5d0 <printf>
    waitForUserToAnalyze();
 130:	e8 db 00 00 00       	call   210 <waitForUserToAnalyze>


    // ============= Fork =============
    printf(1,"Forking..\n");
 135:	58                   	pop    %eax
 136:	5a                   	pop    %edx
 137:	68 94 0a 00 00       	push   $0xa94
 13c:	6a 01                	push   $0x1
 13e:	e8 8d 04 00 00       	call   5d0 <printf>
    int pid = fork();
 143:	e8 32 03 00 00       	call   47a <fork>
    if(pid != 0){
 148:	83 c4 10             	add    $0x10,%esp
 14b:	85 c0                	test   %eax,%eax
 14d:	74 72                	je     1c1 <main+0x1c1>
        //parent
        sleep(2);
 14f:	83 ec 0c             	sub    $0xc,%esp
    }

	
    // ============= Free Pages =============
	printf(1,"Freeing pages..\n");
	for(i=0; i < (FREE_SPACE_ON_RAM*2); i++){
 152:	31 db                	xor    %ebx,%ebx
    // ============= Fork =============
    printf(1,"Forking..\n");
    int pid = fork();
    if(pid != 0){
        //parent
        sleep(2);
 154:	6a 02                	push   $0x2
 156:	e8 b7 03 00 00       	call   512 <sleep>
        wait();
 15b:	e8 2a 03 00 00       	call   48a <wait>
        printf(1,"Parent:: Hello\n");
 160:	5e                   	pop    %esi
 161:	5f                   	pop    %edi
 162:	68 9f 0a 00 00       	push   $0xa9f
 167:	6a 01                	push   $0x1
 169:	e8 62 04 00 00       	call   5d0 <printf>
        waitForUserToAnalyze();
 16e:	e8 9d 00 00 00       	call   210 <waitForUserToAnalyze>
        exit();
    }

	
    // ============= Free Pages =============
	printf(1,"Freeing pages..\n");
 173:	58                   	pop    %eax
 174:	5a                   	pop    %edx
 175:	68 af 0a 00 00       	push   $0xaaf
 17a:	6a 01                	push   $0x1
 17c:	e8 4f 04 00 00       	call   5d0 <printf>
 181:	83 c4 10             	add    $0x10,%esp
 184:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
	for(i=0; i < (FREE_SPACE_ON_RAM*2); i++){
		pages[i] = sbrk(-PGSIZE);
 188:	83 ec 0c             	sub    $0xc,%esp
 18b:	68 00 f0 ff ff       	push   $0xfffff000
 190:	e8 75 03 00 00       	call   50a <sbrk>
		printf(1, "page #%d at address: %x\n", i, pages[i]);
 195:	50                   	push   %eax
 196:	53                   	push   %ebx
    }

	
    // ============= Free Pages =============
	printf(1,"Freeing pages..\n");
	for(i=0; i < (FREE_SPACE_ON_RAM*2); i++){
 197:	83 c3 01             	add    $0x1,%ebx
		pages[i] = sbrk(-PGSIZE);
		printf(1, "page #%d at address: %x\n", i, pages[i]);
 19a:	68 4a 0a 00 00       	push   $0xa4a
 19f:	6a 01                	push   $0x1
 1a1:	e8 2a 04 00 00       	call   5d0 <printf>
    }

	
    // ============= Free Pages =============
	printf(1,"Freeing pages..\n");
	for(i=0; i < (FREE_SPACE_ON_RAM*2); i++){
 1a6:	83 c4 20             	add    $0x20,%esp
 1a9:	83 fb 18             	cmp    $0x18,%ebx
 1ac:	75 da                	jne    188 <main+0x188>
		pages[i] = sbrk(-PGSIZE);
		printf(1, "page #%d at address: %x\n", i, pages[i]);
	}

	//Finish testing
	printf(1,"All tests finished successfully!\n");
 1ae:	50                   	push   %eax
 1af:	50                   	push   %eax
 1b0:	68 08 0a 00 00       	push   $0xa08
 1b5:	6a 01                	push   $0x1
 1b7:	e8 14 04 00 00       	call   5d0 <printf>
	exit();
 1bc:	e8 c1 02 00 00       	call   482 <exit>
        printf(1,"Parent:: Hello\n");
        waitForUserToAnalyze();
    }
    else{
        //son
        printf(1,"Son:: accessing pages 0,1,2,5,14\n");
 1c1:	52                   	push   %edx
 1c2:	52                   	push   %edx
 1c3:	68 e4 09 00 00       	push   $0x9e4
 1c8:	6a 01                	push   $0x1
 1ca:	e8 01 04 00 00       	call   5d0 <printf>
        pages[0][0]=1;
        pages[1][0]=1;
        pages[2][0]=1;
        pages[5][0]=1;
 1cf:	8b 85 74 ff ff ff    	mov    -0x8c(%ebp),%eax
        waitForUserToAnalyze();
    }
    else{
        //son
        printf(1,"Son:: accessing pages 0,1,2,5,14\n");
        pages[0][0]=1;
 1d5:	c6 07 01             	movb   $0x1,(%edi)
        pages[1][0]=1;
 1d8:	c6 06 01             	movb   $0x1,(%esi)
        pages[2][0]=1;
 1db:	c6 03 01             	movb   $0x1,(%ebx)
        pages[5][0]=1;
 1de:	c6 00 01             	movb   $0x1,(%eax)
        pages[14][0]=1;
 1e1:	8b 85 70 ff ff ff    	mov    -0x90(%ebp),%eax
 1e7:	c6 00 01             	movb   $0x1,(%eax)
        printf(1,"No page faults should occur!\n");
 1ea:	59                   	pop    %ecx
 1eb:	5b                   	pop    %ebx
 1ec:	68 c0 0a 00 00       	push   $0xac0
 1f1:	6a 01                	push   $0x1
 1f3:	e8 d8 03 00 00       	call   5d0 <printf>
        waitForUserToAnalyze();
 1f8:	e8 13 00 00 00       	call   210 <waitForUserToAnalyze>
        exit();
 1fd:	e8 80 02 00 00       	call   482 <exit>
 202:	66 90                	xchg   %ax,%ax
 204:	66 90                	xchg   %ax,%ax
 206:	66 90                	xchg   %ax,%ax
 208:	66 90                	xchg   %ax,%ax
 20a:	66 90                	xchg   %ax,%ax
 20c:	66 90                	xchg   %ax,%ax
 20e:	66 90                	xchg   %ax,%ax

00000210 <waitForUserToAnalyze>:
	printf(1,"All tests finished successfully!\n");
	exit();
	return 0;
}

void waitForUserToAnalyze(){
 210:	55                   	push   %ebp
 211:	89 e5                	mov    %esp,%ebp
 213:	83 ec 20             	sub    $0x20,%esp
    char buffer[10];
	printf(1,"Analyze using <CTRL+P>, press ENTER to continue...\n");
 216:	68 f0 08 00 00       	push   $0x8f0
 21b:	6a 01                	push   $0x1
 21d:	e8 ae 03 00 00       	call   5d0 <printf>
	gets(buffer,3);
 222:	58                   	pop    %eax
 223:	8d 45 ee             	lea    -0x12(%ebp),%eax
 226:	5a                   	pop    %edx
 227:	6a 03                	push   $0x3
 229:	50                   	push   %eax
 22a:	e8 21 01 00 00       	call   350 <gets>
}
 22f:	83 c4 10             	add    $0x10,%esp
 232:	c9                   	leave  
 233:	c3                   	ret    
 234:	66 90                	xchg   %ax,%ax
 236:	66 90                	xchg   %ax,%ax
 238:	66 90                	xchg   %ax,%ax
 23a:	66 90                	xchg   %ax,%ax
 23c:	66 90                	xchg   %ax,%ax
 23e:	66 90                	xchg   %ax,%ax

00000240 <strcpy>:
#include "user.h"
#include "x86.h"

char*
strcpy(char *s, char *t)
{
 240:	55                   	push   %ebp
 241:	89 e5                	mov    %esp,%ebp
 243:	53                   	push   %ebx
 244:	8b 45 08             	mov    0x8(%ebp),%eax
 247:	8b 4d 0c             	mov    0xc(%ebp),%ecx
  char *os;

  os = s;
  while((*s++ = *t++) != 0)
 24a:	89 c2                	mov    %eax,%edx
 24c:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
 250:	83 c1 01             	add    $0x1,%ecx
 253:	0f b6 59 ff          	movzbl -0x1(%ecx),%ebx
 257:	83 c2 01             	add    $0x1,%edx
 25a:	84 db                	test   %bl,%bl
 25c:	88 5a ff             	mov    %bl,-0x1(%edx)
 25f:	75 ef                	jne    250 <strcpy+0x10>
    ;
  return os;
}
 261:	5b                   	pop    %ebx
 262:	5d                   	pop    %ebp
 263:	c3                   	ret    
 264:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
 26a:	8d bf 00 00 00 00    	lea    0x0(%edi),%edi

00000270 <strcmp>:

int
strcmp(const char *p, const char *q)
{
 270:	55                   	push   %ebp
 271:	89 e5                	mov    %esp,%ebp
 273:	56                   	push   %esi
 274:	53                   	push   %ebx
 275:	8b 55 08             	mov    0x8(%ebp),%edx
 278:	8b 4d 0c             	mov    0xc(%ebp),%ecx
  while(*p && *p == *q)
 27b:	0f b6 02             	movzbl (%edx),%eax
 27e:	0f b6 19             	movzbl (%ecx),%ebx
 281:	84 c0                	test   %al,%al
 283:	75 1e                	jne    2a3 <strcmp+0x33>
 285:	eb 29                	jmp    2b0 <strcmp+0x40>
 287:	89 f6                	mov    %esi,%esi
 289:	8d bc 27 00 00 00 00 	lea    0x0(%edi,%eiz,1),%edi
    p++, q++;
 290:	83 c2 01             	add    $0x1,%edx
}

int
strcmp(const char *p, const char *q)
{
  while(*p && *p == *q)
 293:	0f b6 02             	movzbl (%edx),%eax
    p++, q++;
 296:	8d 71 01             	lea    0x1(%ecx),%esi
}

int
strcmp(const char *p, const char *q)
{
  while(*p && *p == *q)
 299:	0f b6 59 01          	movzbl 0x1(%ecx),%ebx
 29d:	84 c0                	test   %al,%al
 29f:	74 0f                	je     2b0 <strcmp+0x40>
 2a1:	89 f1                	mov    %esi,%ecx
 2a3:	38 d8                	cmp    %bl,%al
 2a5:	74 e9                	je     290 <strcmp+0x20>
    p++, q++;
  return (uchar)*p - (uchar)*q;
 2a7:	29 d8                	sub    %ebx,%eax
}
 2a9:	5b                   	pop    %ebx
 2aa:	5e                   	pop    %esi
 2ab:	5d                   	pop    %ebp
 2ac:	c3                   	ret    
 2ad:	8d 76 00             	lea    0x0(%esi),%esi
}

int
strcmp(const char *p, const char *q)
{
  while(*p && *p == *q)
 2b0:	31 c0                	xor    %eax,%eax
    p++, q++;
  return (uchar)*p - (uchar)*q;
 2b2:	29 d8                	sub    %ebx,%eax
}
 2b4:	5b                   	pop    %ebx
 2b5:	5e                   	pop    %esi
 2b6:	5d                   	pop    %ebp
 2b7:	c3                   	ret    
 2b8:	90                   	nop
 2b9:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi

000002c0 <strlen>:

uint
strlen(char *s)
{
 2c0:	55                   	push   %ebp
 2c1:	89 e5                	mov    %esp,%ebp
 2c3:	8b 4d 08             	mov    0x8(%ebp),%ecx
  int n;

  for(n = 0; s[n]; n++)
 2c6:	80 39 00             	cmpb   $0x0,(%ecx)
 2c9:	74 12                	je     2dd <strlen+0x1d>
 2cb:	31 d2                	xor    %edx,%edx
 2cd:	8d 76 00             	lea    0x0(%esi),%esi
 2d0:	83 c2 01             	add    $0x1,%edx
 2d3:	80 3c 11 00          	cmpb   $0x0,(%ecx,%edx,1)
 2d7:	89 d0                	mov    %edx,%eax
 2d9:	75 f5                	jne    2d0 <strlen+0x10>
    ;
  return n;
}
 2db:	5d                   	pop    %ebp
 2dc:	c3                   	ret    
uint
strlen(char *s)
{
  int n;

  for(n = 0; s[n]; n++)
 2dd:	31 c0                	xor    %eax,%eax
    ;
  return n;
}
 2df:	5d                   	pop    %ebp
 2e0:	c3                   	ret    
 2e1:	eb 0d                	jmp    2f0 <memset>
 2e3:	90                   	nop
 2e4:	90                   	nop
 2e5:	90                   	nop
 2e6:	90                   	nop
 2e7:	90                   	nop
 2e8:	90                   	nop
 2e9:	90                   	nop
 2ea:	90                   	nop
 2eb:	90                   	nop
 2ec:	90                   	nop
 2ed:	90                   	nop
 2ee:	90                   	nop
 2ef:	90                   	nop

000002f0 <memset>:

void*
memset(void *dst, int c, uint n)
{
 2f0:	55                   	push   %ebp
 2f1:	89 e5                	mov    %esp,%ebp
 2f3:	57                   	push   %edi
 2f4:	8b 55 08             	mov    0x8(%ebp),%edx
}

static inline void
stosb(void *addr, int data, int cnt)
{
  asm volatile("cld; rep stosb" :
 2f7:	8b 4d 10             	mov    0x10(%ebp),%ecx
 2fa:	8b 45 0c             	mov    0xc(%ebp),%eax
 2fd:	89 d7                	mov    %edx,%edi
 2ff:	fc                   	cld    
 300:	f3 aa                	rep stos %al,%es:(%edi)
  stosb(dst, c, n);
  return dst;
}
 302:	89 d0                	mov    %edx,%eax
 304:	5f                   	pop    %edi
 305:	5d                   	pop    %ebp
 306:	c3                   	ret    
 307:	89 f6                	mov    %esi,%esi
 309:	8d bc 27 00 00 00 00 	lea    0x0(%edi,%eiz,1),%edi

00000310 <strchr>:

char*
strchr(const char *s, char c)
{
 310:	55                   	push   %ebp
 311:	89 e5                	mov    %esp,%ebp
 313:	53                   	push   %ebx
 314:	8b 45 08             	mov    0x8(%ebp),%eax
 317:	8b 5d 0c             	mov    0xc(%ebp),%ebx
  for(; *s; s++)
 31a:	0f b6 10             	movzbl (%eax),%edx
 31d:	84 d2                	test   %dl,%dl
 31f:	74 1d                	je     33e <strchr+0x2e>
    if(*s == c)
 321:	38 d3                	cmp    %dl,%bl
 323:	89 d9                	mov    %ebx,%ecx
 325:	75 0d                	jne    334 <strchr+0x24>
 327:	eb 17                	jmp    340 <strchr+0x30>
 329:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
 330:	38 ca                	cmp    %cl,%dl
 332:	74 0c                	je     340 <strchr+0x30>
}

char*
strchr(const char *s, char c)
{
  for(; *s; s++)
 334:	83 c0 01             	add    $0x1,%eax
 337:	0f b6 10             	movzbl (%eax),%edx
 33a:	84 d2                	test   %dl,%dl
 33c:	75 f2                	jne    330 <strchr+0x20>
    if(*s == c)
      return (char*)s;
  return 0;
 33e:	31 c0                	xor    %eax,%eax
}
 340:	5b                   	pop    %ebx
 341:	5d                   	pop    %ebp
 342:	c3                   	ret    
 343:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
 349:	8d bc 27 00 00 00 00 	lea    0x0(%edi,%eiz,1),%edi

00000350 <gets>:

char*
gets(char *buf, int max)
{
 350:	55                   	push   %ebp
 351:	89 e5                	mov    %esp,%ebp
 353:	57                   	push   %edi
 354:	56                   	push   %esi
 355:	53                   	push   %ebx
  int i, cc;
  char c;

  for(i=0; i+1 < max; ){
 356:	31 f6                	xor    %esi,%esi
    cc = read(0, &c, 1);
 358:	8d 7d e7             	lea    -0x19(%ebp),%edi
  return 0;
}

char*
gets(char *buf, int max)
{
 35b:	83 ec 1c             	sub    $0x1c,%esp
  int i, cc;
  char c;

  for(i=0; i+1 < max; ){
 35e:	eb 29                	jmp    389 <gets+0x39>
    cc = read(0, &c, 1);
 360:	83 ec 04             	sub    $0x4,%esp
 363:	6a 01                	push   $0x1
 365:	57                   	push   %edi
 366:	6a 00                	push   $0x0
 368:	e8 2d 01 00 00       	call   49a <read>
    if(cc < 1)
 36d:	83 c4 10             	add    $0x10,%esp
 370:	85 c0                	test   %eax,%eax
 372:	7e 1d                	jle    391 <gets+0x41>
      break;
    buf[i++] = c;
 374:	0f b6 45 e7          	movzbl -0x19(%ebp),%eax
 378:	8b 55 08             	mov    0x8(%ebp),%edx
 37b:	89 de                	mov    %ebx,%esi
    if(c == '\n' || c == '\r')
 37d:	3c 0a                	cmp    $0xa,%al

  for(i=0; i+1 < max; ){
    cc = read(0, &c, 1);
    if(cc < 1)
      break;
    buf[i++] = c;
 37f:	88 44 1a ff          	mov    %al,-0x1(%edx,%ebx,1)
    if(c == '\n' || c == '\r')
 383:	74 1b                	je     3a0 <gets+0x50>
 385:	3c 0d                	cmp    $0xd,%al
 387:	74 17                	je     3a0 <gets+0x50>
gets(char *buf, int max)
{
  int i, cc;
  char c;

  for(i=0; i+1 < max; ){
 389:	8d 5e 01             	lea    0x1(%esi),%ebx
 38c:	3b 5d 0c             	cmp    0xc(%ebp),%ebx
 38f:	7c cf                	jl     360 <gets+0x10>
      break;
    buf[i++] = c;
    if(c == '\n' || c == '\r')
      break;
  }
  buf[i] = '\0';
 391:	8b 45 08             	mov    0x8(%ebp),%eax
 394:	c6 04 30 00          	movb   $0x0,(%eax,%esi,1)
  return buf;
}
 398:	8d 65 f4             	lea    -0xc(%ebp),%esp
 39b:	5b                   	pop    %ebx
 39c:	5e                   	pop    %esi
 39d:	5f                   	pop    %edi
 39e:	5d                   	pop    %ebp
 39f:	c3                   	ret    
      break;
    buf[i++] = c;
    if(c == '\n' || c == '\r')
      break;
  }
  buf[i] = '\0';
 3a0:	8b 45 08             	mov    0x8(%ebp),%eax
gets(char *buf, int max)
{
  int i, cc;
  char c;

  for(i=0; i+1 < max; ){
 3a3:	89 de                	mov    %ebx,%esi
      break;
    buf[i++] = c;
    if(c == '\n' || c == '\r')
      break;
  }
  buf[i] = '\0';
 3a5:	c6 04 30 00          	movb   $0x0,(%eax,%esi,1)
  return buf;
}
 3a9:	8d 65 f4             	lea    -0xc(%ebp),%esp
 3ac:	5b                   	pop    %ebx
 3ad:	5e                   	pop    %esi
 3ae:	5f                   	pop    %edi
 3af:	5d                   	pop    %ebp
 3b0:	c3                   	ret    
 3b1:	eb 0d                	jmp    3c0 <stat>
 3b3:	90                   	nop
 3b4:	90                   	nop
 3b5:	90                   	nop
 3b6:	90                   	nop
 3b7:	90                   	nop
 3b8:	90                   	nop
 3b9:	90                   	nop
 3ba:	90                   	nop
 3bb:	90                   	nop
 3bc:	90                   	nop
 3bd:	90                   	nop
 3be:	90                   	nop
 3bf:	90                   	nop

000003c0 <stat>:

int
stat(char *n, struct stat *st)
{
 3c0:	55                   	push   %ebp
 3c1:	89 e5                	mov    %esp,%ebp
 3c3:	56                   	push   %esi
 3c4:	53                   	push   %ebx
  int fd;
  int r;

  fd = open(n, O_RDONLY);
 3c5:	83 ec 08             	sub    $0x8,%esp
 3c8:	6a 00                	push   $0x0
 3ca:	ff 75 08             	pushl  0x8(%ebp)
 3cd:	e8 f0 00 00 00       	call   4c2 <open>
  if(fd < 0)
 3d2:	83 c4 10             	add    $0x10,%esp
 3d5:	85 c0                	test   %eax,%eax
 3d7:	78 27                	js     400 <stat+0x40>
    return -1;
  r = fstat(fd, st);
 3d9:	83 ec 08             	sub    $0x8,%esp
 3dc:	ff 75 0c             	pushl  0xc(%ebp)
 3df:	89 c3                	mov    %eax,%ebx
 3e1:	50                   	push   %eax
 3e2:	e8 f3 00 00 00       	call   4da <fstat>
 3e7:	89 c6                	mov    %eax,%esi
  close(fd);
 3e9:	89 1c 24             	mov    %ebx,(%esp)
 3ec:	e8 b9 00 00 00       	call   4aa <close>
  return r;
 3f1:	83 c4 10             	add    $0x10,%esp
 3f4:	89 f0                	mov    %esi,%eax
}
 3f6:	8d 65 f8             	lea    -0x8(%ebp),%esp
 3f9:	5b                   	pop    %ebx
 3fa:	5e                   	pop    %esi
 3fb:	5d                   	pop    %ebp
 3fc:	c3                   	ret    
 3fd:	8d 76 00             	lea    0x0(%esi),%esi
  int fd;
  int r;

  fd = open(n, O_RDONLY);
  if(fd < 0)
    return -1;
 400:	b8 ff ff ff ff       	mov    $0xffffffff,%eax
 405:	eb ef                	jmp    3f6 <stat+0x36>
 407:	89 f6                	mov    %esi,%esi
 409:	8d bc 27 00 00 00 00 	lea    0x0(%edi,%eiz,1),%edi

00000410 <atoi>:
  return r;
}

int
atoi(const char *s)
{
 410:	55                   	push   %ebp
 411:	89 e5                	mov    %esp,%ebp
 413:	53                   	push   %ebx
 414:	8b 4d 08             	mov    0x8(%ebp),%ecx
  int n;

  n = 0;
  while('0' <= *s && *s <= '9')
 417:	0f be 11             	movsbl (%ecx),%edx
 41a:	8d 42 d0             	lea    -0x30(%edx),%eax
 41d:	3c 09                	cmp    $0x9,%al
 41f:	b8 00 00 00 00       	mov    $0x0,%eax
 424:	77 1f                	ja     445 <atoi+0x35>
 426:	8d 76 00             	lea    0x0(%esi),%esi
 429:	8d bc 27 00 00 00 00 	lea    0x0(%edi,%eiz,1),%edi
    n = n*10 + *s++ - '0';
 430:	8d 04 80             	lea    (%eax,%eax,4),%eax
 433:	83 c1 01             	add    $0x1,%ecx
 436:	8d 44 42 d0          	lea    -0x30(%edx,%eax,2),%eax
atoi(const char *s)
{
  int n;

  n = 0;
  while('0' <= *s && *s <= '9')
 43a:	0f be 11             	movsbl (%ecx),%edx
 43d:	8d 5a d0             	lea    -0x30(%edx),%ebx
 440:	80 fb 09             	cmp    $0x9,%bl
 443:	76 eb                	jbe    430 <atoi+0x20>
    n = n*10 + *s++ - '0';
  return n;
}
 445:	5b                   	pop    %ebx
 446:	5d                   	pop    %ebp
 447:	c3                   	ret    
 448:	90                   	nop
 449:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi

00000450 <memmove>:

void*
memmove(void *vdst, void *vsrc, int n)
{
 450:	55                   	push   %ebp
 451:	89 e5                	mov    %esp,%ebp
 453:	56                   	push   %esi
 454:	53                   	push   %ebx
 455:	8b 5d 10             	mov    0x10(%ebp),%ebx
 458:	8b 45 08             	mov    0x8(%ebp),%eax
 45b:	8b 75 0c             	mov    0xc(%ebp),%esi
  char *dst, *src;

  dst = vdst;
  src = vsrc;
  while(n-- > 0)
 45e:	85 db                	test   %ebx,%ebx
 460:	7e 14                	jle    476 <memmove+0x26>
 462:	31 d2                	xor    %edx,%edx
 464:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
    *dst++ = *src++;
 468:	0f b6 0c 16          	movzbl (%esi,%edx,1),%ecx
 46c:	88 0c 10             	mov    %cl,(%eax,%edx,1)
 46f:	83 c2 01             	add    $0x1,%edx
{
  char *dst, *src;

  dst = vdst;
  src = vsrc;
  while(n-- > 0)
 472:	39 da                	cmp    %ebx,%edx
 474:	75 f2                	jne    468 <memmove+0x18>
    *dst++ = *src++;
  return vdst;
}
 476:	5b                   	pop    %ebx
 477:	5e                   	pop    %esi
 478:	5d                   	pop    %ebp
 479:	c3                   	ret    

0000047a <fork>:
  name: \
    movl $SYS_ ## name, %eax; \
    int $T_SYSCALL; \
    ret

SYSCALL(fork)
 47a:	b8 01 00 00 00       	mov    $0x1,%eax
 47f:	cd 40                	int    $0x40
 481:	c3                   	ret    

00000482 <exit>:
SYSCALL(exit)
 482:	b8 02 00 00 00       	mov    $0x2,%eax
 487:	cd 40                	int    $0x40
 489:	c3                   	ret    

0000048a <wait>:
SYSCALL(wait)
 48a:	b8 03 00 00 00       	mov    $0x3,%eax
 48f:	cd 40                	int    $0x40
 491:	c3                   	ret    

00000492 <pipe>:
SYSCALL(pipe)
 492:	b8 04 00 00 00       	mov    $0x4,%eax
 497:	cd 40                	int    $0x40
 499:	c3                   	ret    

0000049a <read>:
SYSCALL(read)
 49a:	b8 05 00 00 00       	mov    $0x5,%eax
 49f:	cd 40                	int    $0x40
 4a1:	c3                   	ret    

000004a2 <write>:
SYSCALL(write)
 4a2:	b8 10 00 00 00       	mov    $0x10,%eax
 4a7:	cd 40                	int    $0x40
 4a9:	c3                   	ret    

000004aa <close>:
SYSCALL(close)
 4aa:	b8 15 00 00 00       	mov    $0x15,%eax
 4af:	cd 40                	int    $0x40
 4b1:	c3                   	ret    

000004b2 <kill>:
SYSCALL(kill)
 4b2:	b8 06 00 00 00       	mov    $0x6,%eax
 4b7:	cd 40                	int    $0x40
 4b9:	c3                   	ret    

000004ba <exec>:
SYSCALL(exec)
 4ba:	b8 07 00 00 00       	mov    $0x7,%eax
 4bf:	cd 40                	int    $0x40
 4c1:	c3                   	ret    

000004c2 <open>:
SYSCALL(open)
 4c2:	b8 0f 00 00 00       	mov    $0xf,%eax
 4c7:	cd 40                	int    $0x40
 4c9:	c3                   	ret    

000004ca <mknod>:
SYSCALL(mknod)
 4ca:	b8 11 00 00 00       	mov    $0x11,%eax
 4cf:	cd 40                	int    $0x40
 4d1:	c3                   	ret    

000004d2 <unlink>:
SYSCALL(unlink)
 4d2:	b8 12 00 00 00       	mov    $0x12,%eax
 4d7:	cd 40                	int    $0x40
 4d9:	c3                   	ret    

000004da <fstat>:
SYSCALL(fstat)
 4da:	b8 08 00 00 00       	mov    $0x8,%eax
 4df:	cd 40                	int    $0x40
 4e1:	c3                   	ret    

000004e2 <link>:
SYSCALL(link)
 4e2:	b8 13 00 00 00       	mov    $0x13,%eax
 4e7:	cd 40                	int    $0x40
 4e9:	c3                   	ret    

000004ea <mkdir>:
SYSCALL(mkdir)
 4ea:	b8 14 00 00 00       	mov    $0x14,%eax
 4ef:	cd 40                	int    $0x40
 4f1:	c3                   	ret    

000004f2 <chdir>:
SYSCALL(chdir)
 4f2:	b8 09 00 00 00       	mov    $0x9,%eax
 4f7:	cd 40                	int    $0x40
 4f9:	c3                   	ret    

000004fa <dup>:
SYSCALL(dup)
 4fa:	b8 0a 00 00 00       	mov    $0xa,%eax
 4ff:	cd 40                	int    $0x40
 501:	c3                   	ret    

00000502 <getpid>:
SYSCALL(getpid)
 502:	b8 0b 00 00 00       	mov    $0xb,%eax
 507:	cd 40                	int    $0x40
 509:	c3                   	ret    

0000050a <sbrk>:
SYSCALL(sbrk)
 50a:	b8 0c 00 00 00       	mov    $0xc,%eax
 50f:	cd 40                	int    $0x40
 511:	c3                   	ret    

00000512 <sleep>:
SYSCALL(sleep)
 512:	b8 0d 00 00 00       	mov    $0xd,%eax
 517:	cd 40                	int    $0x40
 519:	c3                   	ret    

0000051a <uptime>:
SYSCALL(uptime)
 51a:	b8 0e 00 00 00       	mov    $0xe,%eax
 51f:	cd 40                	int    $0x40
 521:	c3                   	ret    
 522:	66 90                	xchg   %ax,%ax
 524:	66 90                	xchg   %ax,%ax
 526:	66 90                	xchg   %ax,%ax
 528:	66 90                	xchg   %ax,%ax
 52a:	66 90                	xchg   %ax,%ax
 52c:	66 90                	xchg   %ax,%ax
 52e:	66 90                	xchg   %ax,%ax

00000530 <printint>:
  write(fd, &c, 1);
}

static void
printint(int fd, int xx, int base, int sgn)
{
 530:	55                   	push   %ebp
 531:	89 e5                	mov    %esp,%ebp
 533:	57                   	push   %edi
 534:	56                   	push   %esi
 535:	53                   	push   %ebx
 536:	89 c6                	mov    %eax,%esi
 538:	83 ec 3c             	sub    $0x3c,%esp
  char buf[16];
  int i, neg;
  uint x;

  neg = 0;
  if(sgn && xx < 0){
 53b:	8b 5d 08             	mov    0x8(%ebp),%ebx
 53e:	85 db                	test   %ebx,%ebx
 540:	74 7e                	je     5c0 <printint+0x90>
 542:	89 d0                	mov    %edx,%eax
 544:	c1 e8 1f             	shr    $0x1f,%eax
 547:	84 c0                	test   %al,%al
 549:	74 75                	je     5c0 <printint+0x90>
    neg = 1;
    x = -xx;
 54b:	89 d0                	mov    %edx,%eax
  int i, neg;
  uint x;

  neg = 0;
  if(sgn && xx < 0){
    neg = 1;
 54d:	c7 45 c4 01 00 00 00 	movl   $0x1,-0x3c(%ebp)
    x = -xx;
 554:	f7 d8                	neg    %eax
 556:	89 75 c0             	mov    %esi,-0x40(%ebp)
  } else {
    x = xx;
  }

  i = 0;
 559:	31 ff                	xor    %edi,%edi
 55b:	8d 5d d7             	lea    -0x29(%ebp),%ebx
 55e:	89 ce                	mov    %ecx,%esi
 560:	eb 08                	jmp    56a <printint+0x3a>
 562:	8d b6 00 00 00 00    	lea    0x0(%esi),%esi
  do{
    buf[i++] = digits[x % base];
 568:	89 cf                	mov    %ecx,%edi
 56a:	31 d2                	xor    %edx,%edx
 56c:	8d 4f 01             	lea    0x1(%edi),%ecx
 56f:	f7 f6                	div    %esi
 571:	0f b6 92 e8 0a 00 00 	movzbl 0xae8(%edx),%edx
  }while((x /= base) != 0);
 578:	85 c0                	test   %eax,%eax
    x = xx;
  }

  i = 0;
  do{
    buf[i++] = digits[x % base];
 57a:	88 14 0b             	mov    %dl,(%ebx,%ecx,1)
  }while((x /= base) != 0);
 57d:	75 e9                	jne    568 <printint+0x38>
  if(neg)
 57f:	8b 45 c4             	mov    -0x3c(%ebp),%eax
 582:	8b 75 c0             	mov    -0x40(%ebp),%esi
 585:	85 c0                	test   %eax,%eax
 587:	74 08                	je     591 <printint+0x61>
    buf[i++] = '-';
 589:	c6 44 0d d8 2d       	movb   $0x2d,-0x28(%ebp,%ecx,1)
 58e:	8d 4f 02             	lea    0x2(%edi),%ecx
 591:	8d 7c 0d d7          	lea    -0x29(%ebp,%ecx,1),%edi
 595:	8d 76 00             	lea    0x0(%esi),%esi
 598:	0f b6 07             	movzbl (%edi),%eax
#include "user.h"

static void
putc(int fd, char c)
{
  write(fd, &c, 1);
 59b:	83 ec 04             	sub    $0x4,%esp
 59e:	83 ef 01             	sub    $0x1,%edi
 5a1:	6a 01                	push   $0x1
 5a3:	53                   	push   %ebx
 5a4:	56                   	push   %esi
 5a5:	88 45 d7             	mov    %al,-0x29(%ebp)
 5a8:	e8 f5 fe ff ff       	call   4a2 <write>
    buf[i++] = digits[x % base];
  }while((x /= base) != 0);
  if(neg)
    buf[i++] = '-';

  while(--i >= 0)
 5ad:	83 c4 10             	add    $0x10,%esp
 5b0:	39 df                	cmp    %ebx,%edi
 5b2:	75 e4                	jne    598 <printint+0x68>
    putc(fd, buf[i]);
}
 5b4:	8d 65 f4             	lea    -0xc(%ebp),%esp
 5b7:	5b                   	pop    %ebx
 5b8:	5e                   	pop    %esi
 5b9:	5f                   	pop    %edi
 5ba:	5d                   	pop    %ebp
 5bb:	c3                   	ret    
 5bc:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
  neg = 0;
  if(sgn && xx < 0){
    neg = 1;
    x = -xx;
  } else {
    x = xx;
 5c0:	89 d0                	mov    %edx,%eax
  static char digits[] = "0123456789ABCDEF";
  char buf[16];
  int i, neg;
  uint x;

  neg = 0;
 5c2:	c7 45 c4 00 00 00 00 	movl   $0x0,-0x3c(%ebp)
 5c9:	eb 8b                	jmp    556 <printint+0x26>
 5cb:	90                   	nop
 5cc:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi

000005d0 <printf>:
}

// Print to the given fd. Only understands %d, %x, %p, %s.
void
printf(int fd, char *fmt, ...)
{
 5d0:	55                   	push   %ebp
 5d1:	89 e5                	mov    %esp,%ebp
 5d3:	57                   	push   %edi
 5d4:	56                   	push   %esi
 5d5:	53                   	push   %ebx
  int c, i, state;
  uint *ap;

  state = 0;
  ap = (uint*)(void*)&fmt + 1;
  for(i = 0; fmt[i]; i++){
 5d6:	8d 45 10             	lea    0x10(%ebp),%eax
}

// Print to the given fd. Only understands %d, %x, %p, %s.
void
printf(int fd, char *fmt, ...)
{
 5d9:	83 ec 2c             	sub    $0x2c,%esp
  int c, i, state;
  uint *ap;

  state = 0;
  ap = (uint*)(void*)&fmt + 1;
  for(i = 0; fmt[i]; i++){
 5dc:	8b 75 0c             	mov    0xc(%ebp),%esi
}

// Print to the given fd. Only understands %d, %x, %p, %s.
void
printf(int fd, char *fmt, ...)
{
 5df:	8b 7d 08             	mov    0x8(%ebp),%edi
  int c, i, state;
  uint *ap;

  state = 0;
  ap = (uint*)(void*)&fmt + 1;
  for(i = 0; fmt[i]; i++){
 5e2:	89 45 d0             	mov    %eax,-0x30(%ebp)
 5e5:	0f b6 1e             	movzbl (%esi),%ebx
 5e8:	83 c6 01             	add    $0x1,%esi
 5eb:	84 db                	test   %bl,%bl
 5ed:	0f 84 b0 00 00 00    	je     6a3 <printf+0xd3>
 5f3:	31 d2                	xor    %edx,%edx
 5f5:	eb 39                	jmp    630 <printf+0x60>
 5f7:	89 f6                	mov    %esi,%esi
 5f9:	8d bc 27 00 00 00 00 	lea    0x0(%edi,%eiz,1),%edi
    c = fmt[i] & 0xff;
    if(state == 0){
      if(c == '%'){
 600:	83 f8 25             	cmp    $0x25,%eax
 603:	89 55 d4             	mov    %edx,-0x2c(%ebp)
        state = '%';
 606:	ba 25 00 00 00       	mov    $0x25,%edx
  state = 0;
  ap = (uint*)(void*)&fmt + 1;
  for(i = 0; fmt[i]; i++){
    c = fmt[i] & 0xff;
    if(state == 0){
      if(c == '%'){
 60b:	74 18                	je     625 <printf+0x55>
#include "user.h"

static void
putc(int fd, char c)
{
  write(fd, &c, 1);
 60d:	8d 45 e2             	lea    -0x1e(%ebp),%eax
 610:	83 ec 04             	sub    $0x4,%esp
 613:	88 5d e2             	mov    %bl,-0x1e(%ebp)
 616:	6a 01                	push   $0x1
 618:	50                   	push   %eax
 619:	57                   	push   %edi
 61a:	e8 83 fe ff ff       	call   4a2 <write>
 61f:	8b 55 d4             	mov    -0x2c(%ebp),%edx
 622:	83 c4 10             	add    $0x10,%esp
 625:	83 c6 01             	add    $0x1,%esi
  int c, i, state;
  uint *ap;

  state = 0;
  ap = (uint*)(void*)&fmt + 1;
  for(i = 0; fmt[i]; i++){
 628:	0f b6 5e ff          	movzbl -0x1(%esi),%ebx
 62c:	84 db                	test   %bl,%bl
 62e:	74 73                	je     6a3 <printf+0xd3>
    c = fmt[i] & 0xff;
    if(state == 0){
 630:	85 d2                	test   %edx,%edx
  uint *ap;

  state = 0;
  ap = (uint*)(void*)&fmt + 1;
  for(i = 0; fmt[i]; i++){
    c = fmt[i] & 0xff;
 632:	0f be cb             	movsbl %bl,%ecx
 635:	0f b6 c3             	movzbl %bl,%eax
    if(state == 0){
 638:	74 c6                	je     600 <printf+0x30>
      if(c == '%'){
        state = '%';
      } else {
        putc(fd, c);
      }
    } else if(state == '%'){
 63a:	83 fa 25             	cmp    $0x25,%edx
 63d:	75 e6                	jne    625 <printf+0x55>
      if(c == 'd'){
 63f:	83 f8 64             	cmp    $0x64,%eax
 642:	0f 84 f8 00 00 00    	je     740 <printf+0x170>
        printint(fd, *ap, 10, 1);
        ap++;
      } else if(c == 'x' || c == 'p'){
 648:	81 e1 f7 00 00 00    	and    $0xf7,%ecx
 64e:	83 f9 70             	cmp    $0x70,%ecx
 651:	74 5d                	je     6b0 <printf+0xe0>
        printint(fd, *ap, 16, 0);
        ap++;
      } else if(c == 's'){
 653:	83 f8 73             	cmp    $0x73,%eax
 656:	0f 84 84 00 00 00    	je     6e0 <printf+0x110>
          s = "(null)";
        while(*s != 0){
          putc(fd, *s);
          s++;
        }
      } else if(c == 'c'){
 65c:	83 f8 63             	cmp    $0x63,%eax
 65f:	0f 84 ea 00 00 00    	je     74f <printf+0x17f>
        putc(fd, *ap);
        ap++;
      } else if(c == '%'){
 665:	83 f8 25             	cmp    $0x25,%eax
 668:	0f 84 c2 00 00 00    	je     730 <printf+0x160>
#include "user.h"

static void
putc(int fd, char c)
{
  write(fd, &c, 1);
 66e:	8d 45 e7             	lea    -0x19(%ebp),%eax
 671:	83 ec 04             	sub    $0x4,%esp
 674:	c6 45 e7 25          	movb   $0x25,-0x19(%ebp)
 678:	6a 01                	push   $0x1
 67a:	50                   	push   %eax
 67b:	57                   	push   %edi
 67c:	e8 21 fe ff ff       	call   4a2 <write>
 681:	83 c4 0c             	add    $0xc,%esp
 684:	8d 45 e6             	lea    -0x1a(%ebp),%eax
 687:	88 5d e6             	mov    %bl,-0x1a(%ebp)
 68a:	6a 01                	push   $0x1
 68c:	50                   	push   %eax
 68d:	57                   	push   %edi
 68e:	83 c6 01             	add    $0x1,%esi
 691:	e8 0c fe ff ff       	call   4a2 <write>
  int c, i, state;
  uint *ap;

  state = 0;
  ap = (uint*)(void*)&fmt + 1;
  for(i = 0; fmt[i]; i++){
 696:	0f b6 5e ff          	movzbl -0x1(%esi),%ebx
#include "user.h"

static void
putc(int fd, char c)
{
  write(fd, &c, 1);
 69a:	83 c4 10             	add    $0x10,%esp
      } else {
        // Unknown % sequence.  Print it to draw attention.
        putc(fd, '%');
        putc(fd, c);
      }
      state = 0;
 69d:	31 d2                	xor    %edx,%edx
  int c, i, state;
  uint *ap;

  state = 0;
  ap = (uint*)(void*)&fmt + 1;
  for(i = 0; fmt[i]; i++){
 69f:	84 db                	test   %bl,%bl
 6a1:	75 8d                	jne    630 <printf+0x60>
        putc(fd, c);
      }
      state = 0;
    }
  }
}
 6a3:	8d 65 f4             	lea    -0xc(%ebp),%esp
 6a6:	5b                   	pop    %ebx
 6a7:	5e                   	pop    %esi
 6a8:	5f                   	pop    %edi
 6a9:	5d                   	pop    %ebp
 6aa:	c3                   	ret    
 6ab:	90                   	nop
 6ac:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
    } else if(state == '%'){
      if(c == 'd'){
        printint(fd, *ap, 10, 1);
        ap++;
      } else if(c == 'x' || c == 'p'){
        printint(fd, *ap, 16, 0);
 6b0:	83 ec 0c             	sub    $0xc,%esp
 6b3:	b9 10 00 00 00       	mov    $0x10,%ecx
 6b8:	6a 00                	push   $0x0
 6ba:	8b 5d d0             	mov    -0x30(%ebp),%ebx
 6bd:	89 f8                	mov    %edi,%eax
 6bf:	8b 13                	mov    (%ebx),%edx
 6c1:	e8 6a fe ff ff       	call   530 <printint>
        ap++;
 6c6:	89 d8                	mov    %ebx,%eax
 6c8:	83 c4 10             	add    $0x10,%esp
      } else {
        // Unknown % sequence.  Print it to draw attention.
        putc(fd, '%');
        putc(fd, c);
      }
      state = 0;
 6cb:	31 d2                	xor    %edx,%edx
      if(c == 'd'){
        printint(fd, *ap, 10, 1);
        ap++;
      } else if(c == 'x' || c == 'p'){
        printint(fd, *ap, 16, 0);
        ap++;
 6cd:	83 c0 04             	add    $0x4,%eax
 6d0:	89 45 d0             	mov    %eax,-0x30(%ebp)
 6d3:	e9 4d ff ff ff       	jmp    625 <printf+0x55>
 6d8:	90                   	nop
 6d9:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
      } else if(c == 's'){
        s = (char*)*ap;
 6e0:	8b 45 d0             	mov    -0x30(%ebp),%eax
 6e3:	8b 18                	mov    (%eax),%ebx
        ap++;
 6e5:	83 c0 04             	add    $0x4,%eax
 6e8:	89 45 d0             	mov    %eax,-0x30(%ebp)
        if(s == 0)
          s = "(null)";
 6eb:	b8 de 0a 00 00       	mov    $0xade,%eax
 6f0:	85 db                	test   %ebx,%ebx
 6f2:	0f 44 d8             	cmove  %eax,%ebx
        while(*s != 0){
 6f5:	0f b6 03             	movzbl (%ebx),%eax
 6f8:	84 c0                	test   %al,%al
 6fa:	74 23                	je     71f <printf+0x14f>
 6fc:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
 700:	88 45 e3             	mov    %al,-0x1d(%ebp)
#include "user.h"

static void
putc(int fd, char c)
{
  write(fd, &c, 1);
 703:	8d 45 e3             	lea    -0x1d(%ebp),%eax
 706:	83 ec 04             	sub    $0x4,%esp
 709:	6a 01                	push   $0x1
        ap++;
        if(s == 0)
          s = "(null)";
        while(*s != 0){
          putc(fd, *s);
          s++;
 70b:	83 c3 01             	add    $0x1,%ebx
#include "user.h"

static void
putc(int fd, char c)
{
  write(fd, &c, 1);
 70e:	50                   	push   %eax
 70f:	57                   	push   %edi
 710:	e8 8d fd ff ff       	call   4a2 <write>
      } else if(c == 's'){
        s = (char*)*ap;
        ap++;
        if(s == 0)
          s = "(null)";
        while(*s != 0){
 715:	0f b6 03             	movzbl (%ebx),%eax
 718:	83 c4 10             	add    $0x10,%esp
 71b:	84 c0                	test   %al,%al
 71d:	75 e1                	jne    700 <printf+0x130>
      } else {
        // Unknown % sequence.  Print it to draw attention.
        putc(fd, '%');
        putc(fd, c);
      }
      state = 0;
 71f:	31 d2                	xor    %edx,%edx
 721:	e9 ff fe ff ff       	jmp    625 <printf+0x55>
 726:	8d 76 00             	lea    0x0(%esi),%esi
 729:	8d bc 27 00 00 00 00 	lea    0x0(%edi,%eiz,1),%edi
#include "user.h"

static void
putc(int fd, char c)
{
  write(fd, &c, 1);
 730:	83 ec 04             	sub    $0x4,%esp
 733:	88 5d e5             	mov    %bl,-0x1b(%ebp)
 736:	8d 45 e5             	lea    -0x1b(%ebp),%eax
 739:	6a 01                	push   $0x1
 73b:	e9 4c ff ff ff       	jmp    68c <printf+0xbc>
      } else {
        putc(fd, c);
      }
    } else if(state == '%'){
      if(c == 'd'){
        printint(fd, *ap, 10, 1);
 740:	83 ec 0c             	sub    $0xc,%esp
 743:	b9 0a 00 00 00       	mov    $0xa,%ecx
 748:	6a 01                	push   $0x1
 74a:	e9 6b ff ff ff       	jmp    6ba <printf+0xea>
 74f:	8b 5d d0             	mov    -0x30(%ebp),%ebx
#include "user.h"

static void
putc(int fd, char c)
{
  write(fd, &c, 1);
 752:	83 ec 04             	sub    $0x4,%esp
 755:	8b 03                	mov    (%ebx),%eax
 757:	6a 01                	push   $0x1
 759:	88 45 e4             	mov    %al,-0x1c(%ebp)
 75c:	8d 45 e4             	lea    -0x1c(%ebp),%eax
 75f:	50                   	push   %eax
 760:	57                   	push   %edi
 761:	e8 3c fd ff ff       	call   4a2 <write>
 766:	e9 5b ff ff ff       	jmp    6c6 <printf+0xf6>
 76b:	66 90                	xchg   %ax,%ax
 76d:	66 90                	xchg   %ax,%ax
 76f:	90                   	nop

00000770 <free>:
static Header base;
static Header *freep;

void
free(void *ap)
{
 770:	55                   	push   %ebp
  Header *bp, *p;

  bp = (Header*)ap - 1;
  for(p = freep; !(bp > p && bp < p->s.ptr); p = p->s.ptr)
 771:	a1 ac 0d 00 00       	mov    0xdac,%eax
static Header base;
static Header *freep;

void
free(void *ap)
{
 776:	89 e5                	mov    %esp,%ebp
 778:	57                   	push   %edi
 779:	56                   	push   %esi
 77a:	53                   	push   %ebx
 77b:	8b 5d 08             	mov    0x8(%ebp),%ebx
  Header *bp, *p;

  bp = (Header*)ap - 1;
  for(p = freep; !(bp > p && bp < p->s.ptr); p = p->s.ptr)
    if(p >= p->s.ptr && (bp > p || bp < p->s.ptr))
 77e:	8b 10                	mov    (%eax),%edx
void
free(void *ap)
{
  Header *bp, *p;

  bp = (Header*)ap - 1;
 780:	8d 4b f8             	lea    -0x8(%ebx),%ecx
  for(p = freep; !(bp > p && bp < p->s.ptr); p = p->s.ptr)
 783:	39 c8                	cmp    %ecx,%eax
 785:	73 19                	jae    7a0 <free+0x30>
 787:	89 f6                	mov    %esi,%esi
 789:	8d bc 27 00 00 00 00 	lea    0x0(%edi,%eiz,1),%edi
 790:	39 d1                	cmp    %edx,%ecx
 792:	72 1c                	jb     7b0 <free+0x40>
    if(p >= p->s.ptr && (bp > p || bp < p->s.ptr))
 794:	39 d0                	cmp    %edx,%eax
 796:	73 18                	jae    7b0 <free+0x40>
static Header base;
static Header *freep;

void
free(void *ap)
{
 798:	89 d0                	mov    %edx,%eax
  Header *bp, *p;

  bp = (Header*)ap - 1;
  for(p = freep; !(bp > p && bp < p->s.ptr); p = p->s.ptr)
 79a:	39 c8                	cmp    %ecx,%eax
    if(p >= p->s.ptr && (bp > p || bp < p->s.ptr))
 79c:	8b 10                	mov    (%eax),%edx
free(void *ap)
{
  Header *bp, *p;

  bp = (Header*)ap - 1;
  for(p = freep; !(bp > p && bp < p->s.ptr); p = p->s.ptr)
 79e:	72 f0                	jb     790 <free+0x20>
    if(p >= p->s.ptr && (bp > p || bp < p->s.ptr))
 7a0:	39 d0                	cmp    %edx,%eax
 7a2:	72 f4                	jb     798 <free+0x28>
 7a4:	39 d1                	cmp    %edx,%ecx
 7a6:	73 f0                	jae    798 <free+0x28>
 7a8:	90                   	nop
 7a9:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
      break;
  if(bp + bp->s.size == p->s.ptr){
 7b0:	8b 73 fc             	mov    -0x4(%ebx),%esi
 7b3:	8d 3c f1             	lea    (%ecx,%esi,8),%edi
 7b6:	39 d7                	cmp    %edx,%edi
 7b8:	74 19                	je     7d3 <free+0x63>
    bp->s.size += p->s.ptr->s.size;
    bp->s.ptr = p->s.ptr->s.ptr;
  } else
    bp->s.ptr = p->s.ptr;
 7ba:	89 53 f8             	mov    %edx,-0x8(%ebx)
  if(p + p->s.size == bp){
 7bd:	8b 50 04             	mov    0x4(%eax),%edx
 7c0:	8d 34 d0             	lea    (%eax,%edx,8),%esi
 7c3:	39 f1                	cmp    %esi,%ecx
 7c5:	74 23                	je     7ea <free+0x7a>
    p->s.size += bp->s.size;
    p->s.ptr = bp->s.ptr;
  } else
    p->s.ptr = bp;
 7c7:	89 08                	mov    %ecx,(%eax)
  freep = p;
 7c9:	a3 ac 0d 00 00       	mov    %eax,0xdac
}
 7ce:	5b                   	pop    %ebx
 7cf:	5e                   	pop    %esi
 7d0:	5f                   	pop    %edi
 7d1:	5d                   	pop    %ebp
 7d2:	c3                   	ret    
  bp = (Header*)ap - 1;
  for(p = freep; !(bp > p && bp < p->s.ptr); p = p->s.ptr)
    if(p >= p->s.ptr && (bp > p || bp < p->s.ptr))
      break;
  if(bp + bp->s.size == p->s.ptr){
    bp->s.size += p->s.ptr->s.size;
 7d3:	03 72 04             	add    0x4(%edx),%esi
 7d6:	89 73 fc             	mov    %esi,-0x4(%ebx)
    bp->s.ptr = p->s.ptr->s.ptr;
 7d9:	8b 10                	mov    (%eax),%edx
 7db:	8b 12                	mov    (%edx),%edx
 7dd:	89 53 f8             	mov    %edx,-0x8(%ebx)
  } else
    bp->s.ptr = p->s.ptr;
  if(p + p->s.size == bp){
 7e0:	8b 50 04             	mov    0x4(%eax),%edx
 7e3:	8d 34 d0             	lea    (%eax,%edx,8),%esi
 7e6:	39 f1                	cmp    %esi,%ecx
 7e8:	75 dd                	jne    7c7 <free+0x57>
    p->s.size += bp->s.size;
 7ea:	03 53 fc             	add    -0x4(%ebx),%edx
    p->s.ptr = bp->s.ptr;
  } else
    p->s.ptr = bp;
  freep = p;
 7ed:	a3 ac 0d 00 00       	mov    %eax,0xdac
    bp->s.size += p->s.ptr->s.size;
    bp->s.ptr = p->s.ptr->s.ptr;
  } else
    bp->s.ptr = p->s.ptr;
  if(p + p->s.size == bp){
    p->s.size += bp->s.size;
 7f2:	89 50 04             	mov    %edx,0x4(%eax)
    p->s.ptr = bp->s.ptr;
 7f5:	8b 53 f8             	mov    -0x8(%ebx),%edx
 7f8:	89 10                	mov    %edx,(%eax)
  } else
    p->s.ptr = bp;
  freep = p;
}
 7fa:	5b                   	pop    %ebx
 7fb:	5e                   	pop    %esi
 7fc:	5f                   	pop    %edi
 7fd:	5d                   	pop    %ebp
 7fe:	c3                   	ret    
 7ff:	90                   	nop

00000800 <malloc>:
  return freep;
}

void*
malloc(uint nbytes)
{
 800:	55                   	push   %ebp
 801:	89 e5                	mov    %esp,%ebp
 803:	57                   	push   %edi
 804:	56                   	push   %esi
 805:	53                   	push   %ebx
 806:	83 ec 0c             	sub    $0xc,%esp
  Header *p, *prevp;
  uint nunits;

  nunits = (nbytes + sizeof(Header) - 1)/sizeof(Header) + 1;
 809:	8b 45 08             	mov    0x8(%ebp),%eax
  if((prevp = freep) == 0){
 80c:	8b 15 ac 0d 00 00    	mov    0xdac,%edx
malloc(uint nbytes)
{
  Header *p, *prevp;
  uint nunits;

  nunits = (nbytes + sizeof(Header) - 1)/sizeof(Header) + 1;
 812:	8d 78 07             	lea    0x7(%eax),%edi
 815:	c1 ef 03             	shr    $0x3,%edi
 818:	83 c7 01             	add    $0x1,%edi
  if((prevp = freep) == 0){
 81b:	85 d2                	test   %edx,%edx
 81d:	0f 84 a3 00 00 00    	je     8c6 <malloc+0xc6>
 823:	8b 02                	mov    (%edx),%eax
 825:	8b 48 04             	mov    0x4(%eax),%ecx
    base.s.ptr = freep = prevp = &base;
    base.s.size = 0;
  }
  for(p = prevp->s.ptr; ; prevp = p, p = p->s.ptr){
    if(p->s.size >= nunits){
 828:	39 cf                	cmp    %ecx,%edi
 82a:	76 74                	jbe    8a0 <malloc+0xa0>
 82c:	81 ff 00 10 00 00    	cmp    $0x1000,%edi
 832:	be 00 10 00 00       	mov    $0x1000,%esi
 837:	8d 1c fd 00 00 00 00 	lea    0x0(,%edi,8),%ebx
 83e:	0f 43 f7             	cmovae %edi,%esi
 841:	ba 00 80 00 00       	mov    $0x8000,%edx
 846:	81 ff ff 0f 00 00    	cmp    $0xfff,%edi
 84c:	0f 46 da             	cmovbe %edx,%ebx
 84f:	eb 10                	jmp    861 <malloc+0x61>
 851:	8d b4 26 00 00 00 00 	lea    0x0(%esi,%eiz,1),%esi
  nunits = (nbytes + sizeof(Header) - 1)/sizeof(Header) + 1;
  if((prevp = freep) == 0){
    base.s.ptr = freep = prevp = &base;
    base.s.size = 0;
  }
  for(p = prevp->s.ptr; ; prevp = p, p = p->s.ptr){
 858:	8b 02                	mov    (%edx),%eax
    if(p->s.size >= nunits){
 85a:	8b 48 04             	mov    0x4(%eax),%ecx
 85d:	39 cf                	cmp    %ecx,%edi
 85f:	76 3f                	jbe    8a0 <malloc+0xa0>
        p->s.size = nunits;
      }
      freep = prevp;
      return (void*)(p + 1);
    }
    if(p == freep)
 861:	39 05 ac 0d 00 00    	cmp    %eax,0xdac
 867:	89 c2                	mov    %eax,%edx
 869:	75 ed                	jne    858 <malloc+0x58>
  char *p;
  Header *hp;

  if(nu < 4096)
    nu = 4096;
  p = sbrk(nu * sizeof(Header));
 86b:	83 ec 0c             	sub    $0xc,%esp
 86e:	53                   	push   %ebx
 86f:	e8 96 fc ff ff       	call   50a <sbrk>
  if(p == (char*)-1)
 874:	83 c4 10             	add    $0x10,%esp
 877:	83 f8 ff             	cmp    $0xffffffff,%eax
 87a:	74 1c                	je     898 <malloc+0x98>
    return 0;
  hp = (Header*)p;
  hp->s.size = nu;
 87c:	89 70 04             	mov    %esi,0x4(%eax)
  free((void*)(hp + 1));
 87f:	83 ec 0c             	sub    $0xc,%esp
 882:	83 c0 08             	add    $0x8,%eax
 885:	50                   	push   %eax
 886:	e8 e5 fe ff ff       	call   770 <free>
  return freep;
 88b:	8b 15 ac 0d 00 00    	mov    0xdac,%edx
      }
      freep = prevp;
      return (void*)(p + 1);
    }
    if(p == freep)
      if((p = morecore(nunits)) == 0)
 891:	83 c4 10             	add    $0x10,%esp
 894:	85 d2                	test   %edx,%edx
 896:	75 c0                	jne    858 <malloc+0x58>
        return 0;
 898:	31 c0                	xor    %eax,%eax
 89a:	eb 1c                	jmp    8b8 <malloc+0xb8>
 89c:	8d 74 26 00          	lea    0x0(%esi,%eiz,1),%esi
    base.s.ptr = freep = prevp = &base;
    base.s.size = 0;
  }
  for(p = prevp->s.ptr; ; prevp = p, p = p->s.ptr){
    if(p->s.size >= nunits){
      if(p->s.size == nunits)
 8a0:	39 cf                	cmp    %ecx,%edi
 8a2:	74 1c                	je     8c0 <malloc+0xc0>
        prevp->s.ptr = p->s.ptr;
      else {
        p->s.size -= nunits;
 8a4:	29 f9                	sub    %edi,%ecx
 8a6:	89 48 04             	mov    %ecx,0x4(%eax)
        p += p->s.size;
 8a9:	8d 04 c8             	lea    (%eax,%ecx,8),%eax
        p->s.size = nunits;
 8ac:	89 78 04             	mov    %edi,0x4(%eax)
      }
      freep = prevp;
 8af:	89 15 ac 0d 00 00    	mov    %edx,0xdac
      return (void*)(p + 1);
 8b5:	83 c0 08             	add    $0x8,%eax
    }
    if(p == freep)
      if((p = morecore(nunits)) == 0)
        return 0;
  }
}
 8b8:	8d 65 f4             	lea    -0xc(%ebp),%esp
 8bb:	5b                   	pop    %ebx
 8bc:	5e                   	pop    %esi
 8bd:	5f                   	pop    %edi
 8be:	5d                   	pop    %ebp
 8bf:	c3                   	ret    
    base.s.size = 0;
  }
  for(p = prevp->s.ptr; ; prevp = p, p = p->s.ptr){
    if(p->s.size >= nunits){
      if(p->s.size == nunits)
        prevp->s.ptr = p->s.ptr;
 8c0:	8b 08                	mov    (%eax),%ecx
 8c2:	89 0a                	mov    %ecx,(%edx)
 8c4:	eb e9                	jmp    8af <malloc+0xaf>
  Header *p, *prevp;
  uint nunits;

  nunits = (nbytes + sizeof(Header) - 1)/sizeof(Header) + 1;
  if((prevp = freep) == 0){
    base.s.ptr = freep = prevp = &base;
 8c6:	c7 05 ac 0d 00 00 b0 	movl   $0xdb0,0xdac
 8cd:	0d 00 00 
 8d0:	c7 05 b0 0d 00 00 b0 	movl   $0xdb0,0xdb0
 8d7:	0d 00 00 
    base.s.size = 0;
 8da:	b8 b0 0d 00 00       	mov    $0xdb0,%eax
 8df:	c7 05 b4 0d 00 00 00 	movl   $0x0,0xdb4
 8e6:	00 00 00 
 8e9:	e9 3e ff ff ff       	jmp    82c <malloc+0x2c>
