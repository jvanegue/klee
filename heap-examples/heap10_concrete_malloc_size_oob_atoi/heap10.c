#include <malloc.h>
#include <stdlib.h>

int main(int argc, char *argv[])
{
  char *a = (char *)malloc(256);
  if (argc <= 1)
    return (0);
  int idx = atoi((const char *) argv[1]);
  a[idx] = 'x';
  return 0;
}
