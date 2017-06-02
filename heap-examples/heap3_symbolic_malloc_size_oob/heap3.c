#include <string.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
  unsigned malloc_size = rand();
  unsigned int index_invalid = rand();
  
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
