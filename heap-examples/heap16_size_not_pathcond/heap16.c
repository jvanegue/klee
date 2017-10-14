#include <string.h>
#include <stdio.h>
#include <stdlib.h>

unsigned int index_invalid = 66000;

int main(int argc, char *argv[])
{
  if (argc != 2) return (-1);
  unsigned int malloc_size = atoi(argv[1]);
  if (malloc_size < 100000 && malloc_size > 65900)
    {
      printf("good path malloc size = %u \n", malloc_size);
      char *a = (char *)malloc(malloc_size);
      if (a != 0)
	a[index_invalid] = 0x00;
    }
  else
    {
      printf("wasted path malloc size = %u \n", malloc_size);
    }
  return 0;
}
