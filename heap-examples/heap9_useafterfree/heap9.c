#include <malloc.h>

int main(int argc, char *argv[])
{
  char *a = (char *)malloc(16);
  a[0] = 'x';
  free(a);
  char *b = (char *)malloc(16);
  a[0] = 'y';
  return 0;
}
