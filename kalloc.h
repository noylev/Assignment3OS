// struct for keeping track of the percent of free physical pages
struct physPagesCounts{
  uint initPagesNo;
  uint currentphysical_pagesNo;
};

extern struct physPagesCounts physPagesCounts;
