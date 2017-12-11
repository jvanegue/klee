//===-- PTest.h --------------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef __COMMON_PTEST_H__
#define __COMMON_PTEST_H__


#ifdef __cplusplus
extern "C" {
#endif

  typedef struct PTestObject PTestObject;
  struct PTestObject {
    char	*name;
    enum	ctype
      {
	EQ  = 0,
	LT  = 1,
	GT  = 2,
	GEQ = 3,
	LEQ = 4,
	NEQ = 5,
      };
    unsigned int  otype;
    unsigned int  numBytes;
    unsigned char *bytes;
  };
  
  typedef struct PTest PTest;
  struct PTest {
    unsigned numObjects;
    PTestObject *objects;
  };

    
  /* return true iff file at path matches KTest header */
  int   pTest_isPTestFile(const char *path);

  /* returns NULL on (unspecified) error */
  PTest* pTest_fromFile(const char *path);

  /* returns 1 on success, 0 on (unspecified) error */
  int   pTest_toFile(PTest *, const char *path);
  
  /* returns total number of object bytes */
  unsigned pTest_numBytes(pTest *);

  void  pTest_free(PTest *);

#ifdef __cplusplus
#endif

#endif
