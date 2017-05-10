#include <malloc.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[])
{
  if (argc != 3)
    return (0);
  
  int len = strlen(argv[1]);
  
  char *a = (char *)malloc(len);
  if (a == NULL)
    return (-1);
  
  int idx = atoi((const char *) argv[2]);
  memcpy(a, "abcd", idx);

  // avoid code being optimized
  return (int)  a[0];
}
