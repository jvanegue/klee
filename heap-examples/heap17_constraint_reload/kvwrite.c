#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <klee/klee.h>

// These functions are shimmed as their semantics is encoded in the constraint transfer functions inside KLEE
int	     kv_write(char *key, char *value, int len) { return (0); }
int	     kv_read(char *key, char *value, int len)  { return (0); }

int main(int argc, char *argv[])
{
  if (argc != 3)
    return (-1);
  char *key = argv[1];
  int klen = strlen(key);
  if (klen == 0)
    return (-1);
  if (!strcmp(key, "fst"))
    {
      char *value = "\xFFval";
      int len = strlen(value);
      kv_write(key, value, len);
    }
  else if (!strcmp(key, "snd"))
    {
      char *value = "\x00val";
      int len = strlen(value);
      kv_write(key, value, len);
    }
  return (0);
}


