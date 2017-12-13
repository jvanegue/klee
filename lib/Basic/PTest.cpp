//===-- PTest.cpp ---------------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "klee/Internal/ADT/PTest.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define PTEST_MAGIC_SIZE 5
#define PTEST_MAGIC "PTEST"

/***/

static int read_uint32(FILE *f, unsigned *value_out) {
  unsigned char data[4];
  if (fread(data, 4, 1, f)!=1)
    return 0;
  *value_out = (((((data[0]<<8) + data[1])<<8) + data[2])<<8) + data[3];
  return 1;
}

static int write_uint32(FILE *f, unsigned value) {
  unsigned char data[4];
  data[0] = value>>24;
  data[1] = value>>16;
  data[2] = value>> 8;
  data[3] = value>> 0;
  return fwrite(data, 1, 4, f)==4;
}

static int read_string(FILE *f, char **value_out) {
  unsigned len;
  if (!read_uint32(f, &len))
    return 0;
  *value_out = (char*) malloc(len+1);
  if (!*value_out)
    return 0;
  if (fread(*value_out, len, 1, f)!=1)
    return 0;
  (*value_out)[len] = 0;
  return 1;
}

static int write_string(FILE *f, const char *value) {
  unsigned len = strlen(value);
  if (!write_uint32(f, len))
    return 0;
  if (fwrite(value, len, 1, f)!=1)
    return 0;
  return 1;
}

static int pTest_checkHeader(FILE *f) {
  char header[PTEST_MAGIC_SIZE];
  if (fread(header, PTEST_MAGIC_SIZE, 1, f)!=1)
    return 0;
  if (memcmp(header, PTEST_MAGIC, PTEST_MAGIC_SIZE))
    return 0;
  return 1;
}

int pTest_isPTestFile(const char *path) {
  FILE *f = fopen(path, "rb");
  int res;
  if (!f)
    return 0;
  res = pTest_checkHeader(f);
  fclose(f);
  return res;
}


PTest *pTest_fromFile(const char *path) {
  FILE *f = fopen(path, "rb");
  PTest *res = 0;
  unsigned i;

  if (!f) 
    goto error;
  if (!pTest_checkHeader(f)) 
    goto error;

  res = (PTest*) calloc(1, sizeof(*res));
  if (!res) 
    goto error;

  if (!read_uint32(f, &res->numObjects))
    goto error;
  res->objects = (PTestObject*) calloc(res->numObjects, sizeof(*res->objects));
  if (!res->objects)
    goto error;
  for (i=0; i<res->numObjects; i++) {
    PTestObject *o = &res->objects[i];
    if (!read_string(f, &o->name))
      goto error;
    if (!read_uint32(f, &o->numBytes))
      goto error;
    o->bytes = (PTestByte*) malloc(o->numBytes * sizeof(PTestByte));
    if (fread(o->bytes, o->numBytes * sizeof(PTestByte), 1, f)!=1)
      goto error;
  }
  fclose(f);
  return res;
  
 error:
  if (res) {
    if (res->objects) {
      for (i=0; i<res->numObjects; i++) {
        PTestObject *bo = &res->objects[i];
        if (bo->name)
          free(bo->name);
        if (bo->bytes)
          free(bo->bytes);
      }
      free(res->objects);
    }
    free(res);
  }
  if (f) fclose(f);
  return 0;
}


int pTest_toFile(PTest *bo, const char *path) {
  FILE *f = fopen(path, "wb");
  unsigned i;

  if (!f) 
    goto error;
  if (fwrite(PTEST_MAGIC, strlen(PTEST_MAGIC), 1, f)!=1)
    goto error;
  if (!write_uint32(f, bo->numObjects))
    goto error;
  for (i=0; i<bo->numObjects; i++) {
    PTestObject *o = &bo->objects[i];
    if (!write_string(f, o->name))
      goto error;
    if (!write_uint32(f, o->numBytes))
      goto error;
    if (fwrite(o->bytes, o->numBytes * sizeof(PTestByte), 1, f)!=1)
      goto error;
  }
  fclose(f);
  return 1;
 error:
  if (f) fclose(f);
  return 0;
}

unsigned pTest_numBytes(PTest *bo) {
  unsigned i, res = 0;
  for (i=0; i<bo->numObjects; i++)
    res += bo->objects[i].numBytes;
  return res;
}

void pTest_free(PTest *bo) {
  unsigned i;
  for (i=0; i<bo->numObjects; i++) {
    free(bo->objects[i].name);
    free(bo->objects[i].bytes);
  }
  free(bo->objects);
  free(bo);
}
