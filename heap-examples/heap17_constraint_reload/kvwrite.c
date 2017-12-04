#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <klee/klee.h>

int	     kv_write(char *key, char *value, int len);
int	     kv_read(char *key, char *value, int len);

int main(int argc, char *argv[])
{
  if (argc != 3)
    return (-1);
  char *key = argv[1];
  int klen = strlen(key);
  char *value = "val";
  int len = strlen(value);
  if (klen == 0 || len < 3)
    return (-1);
  if (!strcmp(key, "fst") || !strcmp(key, "snd"))
    {
      kv_write(key, value, len);
      printf("WRITE: key[%s] = value[%s] \n", key, value);
      return (0);
    }
  return (-1);
}


