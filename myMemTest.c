// #include "types.h"
// #include "user.h"
// #include "fcntl.h"

// int
// main(void)
// {
// 	int array [1048576];
// 	array[0]=4;
// 	array[8000]=21;
// 	array[400000]=array[0]+array[8000];
// 	exit();
// }
#include "types.h"
#include "user.h"
#include "stat.h"
#include "syscall.h"

#define PGSIZE 4096
#define FREE_SPACE_ON_RAM 12
void waitForUserToAnalyze();


int main(int argc, char *argv[]){
	#ifdef LIFO
		printf(1,"Testing LIFO MODE:\npress Enter...\n");
	#elif LAP
		printf(1,"Testing LAP MODE:\npress Enter...\n");
	#elif SCFIFO
        printf(1,"Testing SCFIFO MODE:\npress Enter...\n");
	#endif
    
    //allocate 12 pages
    char* pages[25];
    int i;
    printf(1,"Allocating 12 pages (0-11)..\n");
    for(i=0; i < FREE_SPACE_ON_RAM; ++i){
        pages[i] = sbrk(PGSIZE);
        printf(1, "page #%d at address: %x\n", i, pages[i]);
    }
    printf(1,"Reached max. number of pages on RAM..\n"); //i=11
    waitForUserToAnalyze();
    
    //access pages
    printf(1,"Accessing pages 0-2\n");
    pages[0][0]=1;
    pages[1][0]=1;
    pages[2][0]=1;
    printf(1,"All pages on RAM, no page faults expected.\n");
    waitForUserToAnalyze();
    
    //allocate 12 more pages
    printf(1,"Allocating 12 more pages (12 swap outs should occur).\n"); //i=22
    int j;
    for(j=0; j<FREE_SPACE_ON_RAM; j++){
    	printf(1, "page #%d at address: %x\n", i, pages[i]);
        pages[i] = sbrk(PGSIZE);
        
        i++;
    }

    // LIFO:	swap only the last page, 15 ||| 1-14 remains
    // SCFIFO:	swap pages 6-15,3-4 ||| 1,2,5 remains
    // LAP:		swap pages 6-15 (6&7 twice) ||| 1-5 remains
    waitForUserToAnalyze();

    printf(1,"Accessing pages 0,1,2,5,14\n");
    pages[0][0]=1;
    pages[1][0]=1;
    pages[2][0]=1;
    pages[5][0]=1;
    pages[14][0]=1;
    printf(1,"Expected page faults:\n[LIFO-1] [SCFIFO-3] [LAP-2]\n");
    waitForUserToAnalyze();


    // ============= Fork =============
    printf(1,"Forking..\n");
    int pid = fork();
    if(pid != 0){
        //parent
        sleep(2);
        wait();
        printf(1,"Parent:: Hello\n");
        waitForUserToAnalyze();
    }
    else{
        //son
        printf(1,"Son:: accessing pages 0,1,2,5,14\n");
        pages[0][0]=1;
        pages[1][0]=1;
        pages[2][0]=1;
        pages[5][0]=1;
        pages[14][0]=1;
        printf(1,"No page faults should occur!\n");
        waitForUserToAnalyze();
        exit();
    }

	
    // ============= Free Pages =============
	printf(1,"Freeing pages..\n");
	for(i=0; i < (FREE_SPACE_ON_RAM*2); i++){
		pages[i] = sbrk(-PGSIZE);
		printf(1, "page #%d at address: %x\n", i, pages[i]);
	}

	//Finish testing
	printf(1,"All tests finished successfully!\n");
	exit();
	return 0;
}

void waitForUserToAnalyze(){
    char buffer[10];
	printf(1,"Analyze using <CTRL+P>, press ENTER to continue...\n");
	gets(buffer,3);
}
