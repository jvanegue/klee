#include <malloc.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
  if (argc <= 1)
    return (0);
  
  int len = strlen(argv[1]);
  
  char *a = (char *)malloc(len);
  if (a == NULL)
    return (-1);
  
  int idx = atoi((const char *) argv[1]);
  a[idx] = 'x';

  
  return 0;
}
