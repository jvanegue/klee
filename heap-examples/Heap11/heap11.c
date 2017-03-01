#include <malloc.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
  if (argc <= 1)
    return (0);
  
  int len = strlen(argv[1]);
  
  char *a = (char *)malloc(len);

  a[0] = 0x00;
  
  //int idx = atoi((const char *) argv[1]);
  //a[idx] = 'x';

  
  return 0;
}
