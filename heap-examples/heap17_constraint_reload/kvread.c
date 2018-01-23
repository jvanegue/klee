#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <klee/klee.h>

int	     kv_write(char *key, char *value, int len) { return (0); }
int	     kv_read(char *key, char *value, int* len) { return (0); }

int main(int argc, char *argv[])
{
  if (argc != 2)
    return (-1);
  char *key = argv[1];
  char value[8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
  int len = 0;
  int klen = strlen(key);
  if (klen == 0)
    return (-1);
  if (!strcmp(key, "fst"))
    { 
      kv_read(key, value, &len);
      unsigned char fst = value[0];
      value[fst] = 0x00;
    }
  else if (!strcmp(key, "snd"))
    {
      kv_read(key, value, &len);
      unsigned char snd = value[0];
      value[snd] = 0x00;
    }
  return (0);
}
