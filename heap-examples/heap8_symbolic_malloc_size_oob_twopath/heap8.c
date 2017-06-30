#include "klee/klee.h"
#include <stdlib.h>

unsigned char bad_food[] = {
  0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90,
};

int main(int argc, char *argv[])
{
  unsigned int malloc_size;

  klee_make_symbolic(&malloc_size, sizeof(malloc_size), "malloc_size");

  char *a = (char *) malloc(malloc_size);    

  if (malloc_size > 10)
    a[20] = 0x42;
  
  return 0;
}
