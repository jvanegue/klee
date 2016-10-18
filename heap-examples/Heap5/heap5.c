#include <string.h>
#include <stdio.h>
#include <stdlib.h>

unsigned int index_invalid = 0;

int fct(int num)
{
  return (num);
}

int main(int argc, char *argv[])
{
  unsigned int malloc_size;

  klee_make_symbolic(&malloc_size, sizeof(malloc_size), "malloc_size");
  //klee_make_symbolic(&index_invalid, sizeof(index_invalid), "index_invalid");

  malloc_size = 0;  
  index_invalid = 0;
  
  //if (malloc_size != 0)
  //{
      char *a = (char *)malloc(malloc_size);
      char *b = (char *)malloc(malloc_size);
      if( (a!=0) && (b!=0))
	{
	  a[index_invalid] = 0x00;
	  free(b);
	}
      //}
  return 0;
}
