#include <string.h>
#include <stdio.h>
#include <stdlib.h>

unsigned int index_invalid = 77;

int fct(int num)
{
  return (num);
}

int main(int argc, char *argv[])
{
  unsigned int malloc_size = rand();
  index_invalid = fct(127);
  //klee_make_symbolic(&malloc_size, sizeof(malloc_size), "malloc_size");
  if (malloc_size != 0)
    {
      char *a = (char *)malloc(malloc_size);
      char *b = (char *)malloc(malloc_size);
      if( (a!=0) && (b!=0))
	{
	  a[index_invalid] = 0x00;
	  free(b);
	}
    }
  return 0;
}
