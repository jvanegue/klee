#include <malloc.h>

int main(int argc, char *argv[])
{
  char *a = (char *) malloc(16);
  a[0] = 'x';
  a[1] = 0x00;
  char b[] = "Hello world";
  printf("%s %s \n", a, b);
  free(a);
  free(b);
  return 0;
}
