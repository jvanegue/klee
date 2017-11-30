#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <klee/klee.h>

int	     kv_write(char *key, char *value, int len);
int	     kv_read(char *key, char *value, int* len);

int main(int argc, char *argv[])
{
  if (argc != 2)
    return (-1);
  char *key = argv[1];
  char *value = NULL;
  int len = 0;
  int klen = strlen(key);
  if (klen == 0)
    return (-1);
  if (!strcmp(key, "fst") || !strcmp(key, "snd"))
    { 
      kv_read(key, value, &len);
      value[1] = 0x00;
      return (0);
    }
  return (-1);
}
