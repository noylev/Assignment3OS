typedef unsigned int   uint;
typedef unsigned short ushort;
typedef unsigned char  uchar;
typedef uint pde_t;

// For page statistics tracking.
struct page_statistics{
  uint inital_number;
  uint current_number;
};

extern struct page_statistics page_statistics;
