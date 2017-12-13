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

  typedef struct PTestByte PTestByte;
  struct PTestByte
  {
    enum	ctype
      {
	SYM = 0,
	EQ  = 1,
	LT  = 2,
	GT  = 3,
	GEQ = 4,
	LEQ = 5,
	NEQ = 6
      };
    unsigned int  otype;    
    unsigned char value;
  };
  
  typedef struct PTestObject PTestObject;
  struct PTestObject {
    char	*name;
    unsigned int numBytes;
    PTestByte   *bytes;
  };
  
  typedef struct PTest PTest;
  struct PTest {
    unsigned int numObjects;
    PTestObject *objects;
  };

  /* return true iff file at path matches KTest header */
  int   pTest_isPTestFile(const char *path);

  /* returns NULL on (unspecified) error */
  PTest* pTest_fromFile(const char *path);

  /* returns 1 on success, 0 on (unspecified) error */
  int   pTest_toFile(PTest *, const char *path);
  
  /* returns total number of object bytes */
  unsigned int pTest_numBytes(PTest *);

  void  pTest_free(PTest *);

#ifdef __cplusplus
}
#endif

#endif
