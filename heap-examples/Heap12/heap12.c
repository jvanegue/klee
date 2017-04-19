#include <malloc.h>
#include <stdlib.h>

struct A
{
  int array[10];
  int x;
};

int main(int argc, char *argv[])
{
  struct A *a = (char *)malloc(sizeof(struct A));
  if (a == NULL)
    return (0);
  int index = atoi(argv[0]);
  if (index > 10)
    return (0);
  a->array[index] = 0;
  return 0;
}
