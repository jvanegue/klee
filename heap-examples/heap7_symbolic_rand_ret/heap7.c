#include <string.h>
#include <stdio.h>
#include <stdlib.h>

unsigned int index_invalid = 77;


int main(int argc, char *argv[])
{
  unsigned int malloc_size = rand();
  index_invalid = 127; 
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
