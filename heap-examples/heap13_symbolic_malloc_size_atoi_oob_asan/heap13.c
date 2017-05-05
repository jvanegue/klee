#include <malloc.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
  if (argc != 2)
    {
      fprintf(stderr, "argc is not 2: terminating \n");
      return (0);
    }
  
  int len = atoi(argv[1]);
  //int idx = atoi(argv[2]);
  
  char *a = (char *)malloc(len);
  if (a == NULL)
    {
      fprintf(stderr, "malloc returned NULL - terminating \n");
      return (-1);
    }

  int idx = 0;
  for (idx = 0; idx < 2048; idx++)
    {
    a[idx] = 0x00;
    *(a + idx) = 0x00;
    }

  fprintf(stderr, "Done\n");
  return 0;
}
