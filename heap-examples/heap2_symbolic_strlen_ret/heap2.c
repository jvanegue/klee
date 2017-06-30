#include <string.h>
#include <stdio.h>
#include <stdlib.h>

unsigned int index_invalid = 77;

int main(int argc, char *argv[])
{
  if (argc != 2) return (-1);  

  unsigned int malloc_size = strlen(argv[1]);
  
  if (malloc_size != 0)
    {
      char *a = (char *)malloc(malloc_size);
      if (a != 0)
	a[index_invalid] = 0x00;
    }
  return 0;
}
