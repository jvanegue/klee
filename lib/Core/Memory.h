//===-- Memory.h ------------------------------------------------*- C++ -*-===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef KLEE_MEMORY_H
#define KLEE_MEMORY_H

#include "Context.h"
#include "klee/Expr.h"

#include "llvm/ADT/StringExtras.h"

#include <vector>
#include <string>

namespace llvm {
  class Value;
}

namespace klee {

class BitArray;
class MemoryManager;
class Solver;
class ArrayCache;

class MemoryObject {
  friend class STPBuilder;
  friend class ObjectState;
  friend class ExecutionState;

private:
  static int counter;
  mutable unsigned refCount;

public:
  unsigned id;

  // Guest address, used a the key in MemoryMap and thus used to find a memory object by address
  // TODO: rename to guest address
  uint64_t address;
  // Points to the memory returned by malloc() on the host
  uint64_t host_address;
  unsigned size;

  // When address and size are symbolic
  ref<Expr> constraint_addr;  
  ref<Expr>  constraint_size;
  ref<Expr>  symbolic_size;
  bool isSizeDynamic;

  mutable std::string name;

  bool isLocal;
  mutable bool isGlobal;
  bool isFixed;

  bool isUserSpecified;

  MemoryManager *parent;

  /// "Location" for which this memory object was allocated. This
  /// should be either the allocating instruction or the global object
  /// it was allocated for (or whatever else makes sense).
  const llvm::Value *allocSite;
  
  /// A list of boolean expressions the user has requested be true of
  /// a counterexample. Mutable since we play a little fast and loose
  /// with allowing it to be added to during execution (although
  /// should sensibly be only at creation time).
  mutable std::vector< ref<Expr> > cexPreferences;

  // DO NOT IMPLEMENT
  MemoryObject(const MemoryObject &b);
  MemoryObject &operator=(const MemoryObject &b);

public:
  // XXX this is just a temp hack, should be removed
  explicit
  MemoryObject(uint64_t _address) 
    : refCount(0),
      id(counter++), 
      address(_address),
      host_address(_address),
      size(0),
      constraint_addr(0),
      constraint_size(0),
      symbolic_size(0),
      isSizeDynamic(false),
      isFixed(true),
      parent(NULL),
      allocSite(0) {
  }

  MemoryObject(ref<Expr> _address, ref<Expr> _size, 
               bool _isLocal, bool _isGlobal, bool _isFixed,
               const llvm::Value *_allocSite,
               MemoryManager *_parent)
    : refCount(0), 
      id(counter++),
      
      address(0),
      size(0),
      constraint_addr(_address),
      constraint_size(_size),

      name("unnamed"),
      isLocal(_isLocal),
      isGlobal(_isGlobal),
      isFixed(_isFixed),
      isUserSpecified(false),
      parent(_parent), 
      allocSite(_allocSite) {
  }


	       
  MemoryObject(uint64_t _address, unsigned _size, 
               bool _isLocal, bool _isGlobal, bool _isFixed,
               const llvm::Value *_allocSite,
               MemoryManager *_parent)
    : refCount(0), 
      id(counter++),

      address(_address),
      host_address(_address),
      size(_size),
      constraint_addr(0),
      constraint_size(0),
      symbolic_size(0),
      isSizeDynamic(false),
      
        name("unnamed"),
      isLocal(_isLocal),
      isGlobal(_isGlobal),
      isFixed(_isFixed),
      isUserSpecified(false),
      parent(_parent), 
      allocSite(_allocSite) {
  }

  ~MemoryObject();

  /// Get an identifying string for this allocation.
  void getAllocInfo(std::string &result) const;

  void setName(std::string name) const {
    this->name = name;
  }

  ref<ConstantExpr> getBaseExpr() const { 
    return ConstantExpr::create(address, Context::get().getPointerWidth());
  }
  ref<ConstantExpr> getSizeExpr() const { 
    return ConstantExpr::create(size, Context::get().getPointerWidth());
  }
  ref<Expr> getOffsetExpr(ref<Expr> pointer) const {
    return SubExpr::create(pointer, getBaseExpr());
  }
  ref<Expr> getBoundsCheckPointer(ref<Expr> pointer) const {
    return getBoundsCheckOffset(getOffsetExpr(pointer));
  }
  ref<Expr> getBoundsCheckPointer(ref<Expr> pointer, unsigned bytes) const {
    return getBoundsCheckOffset(getOffsetExpr(pointer), bytes);
  }

  ref<Expr> getBoundsCheckOffset(ref<Expr> offset) const {
    if(!isSizeDynamic)
    {
      if (size==0) {
        return EqExpr::create(offset, 
                              ConstantExpr::alloc(0, Context::get().getPointerWidth()));
      } else {
        return UltExpr::create(offset, getSizeExpr());
      }
    } else
    {
      return UltExpr::create(offset, symbolic_size);
      //return UleExpr::create(offset, 
      //                  AddExpr::create(symbolic_size,
      //		                ConstantExpr::alloc(1,Context::get().getPointerWidth())));
    }
  }

  ref<Expr> getBoundsCheckOffset(ref<Expr> offset, unsigned bytes) const {
    unsigned  int width = Context::get().getPointerWidth();
    if(!isSizeDynamic)
    {
      if (bytes<=size) {
	ref<Expr> add = AddExpr::create(offset, ConstantExpr::alloc(bytes, width));
	
	// JV: should not that be Signed lower than? (e.g. if offset is negative)
	// Or: add another constraint offset >= 0 since this should never happen
	
	ref<Expr> ult = UltExpr::create(add, ConstantExpr::alloc(size + 1, width));
	return (ult);
      }

      // This is never true, will always trigger OOB warning
      else {
        return ConstantExpr::alloc(0, Expr::Bool);
      }
    }
    else
    {
      ref<Expr> add = AddExpr::create(offset, ConstantExpr::alloc(bytes - 1, width));
      ref<Expr> ult = UltExpr::create(add, symbolic_size);
      return (ult);
    }
  }

};

class ObjectState {
private:
  friend class AddressSpace;
  unsigned copyOnWriteOwner; // exclusively for AddressSpace

  friend class ObjectHolder;
  unsigned refCount;

  const MemoryObject *object;

  uint8_t *concreteStore;
  // XXX cleanup name of flushMask (its backwards or something)
  BitArray *concreteMask;

  // mutable because may need flushed during read of const
  mutable BitArray *flushMask;

  ref<Expr> *knownSymbolics;

  // mutable because we may need flush during read of const
  mutable UpdateList updates;

public:
  unsigned size;

  bool readOnly;

public:
  /// Create a new object state for the given memory object with concrete
  /// contents. The initial contents are undefined, it is the callers
  /// responsibility to initialize the object contents appropriately.
  ObjectState(const MemoryObject *mo);

  /// Create a new object state for the given memory object with symbolic
  /// contents.
  ObjectState(const MemoryObject *mo, const Array *array);

  ObjectState(const ObjectState &os);
  ~ObjectState();

  const MemoryObject *getObject() const { return object; }

  void setReadOnly(bool ro) { readOnly = ro; }

  // make contents all concrete and zero
  void initializeToZero();
  // make contents all concrete and random
  void initializeToRandom();

  ref<Expr> read(ref<Expr> offset, Expr::Width width) const;
  ref<Expr> read(unsigned offset, Expr::Width width) const;
  ref<Expr> read8(unsigned offset) const;

  // return bytes written.
  void write(unsigned offset, ref<Expr> value);
  void write(ref<Expr> offset, ref<Expr> value);

  void write8(unsigned offset, uint8_t value);
  void write16(unsigned offset, uint16_t value);
  void write32(unsigned offset, uint32_t value);
  void write64(unsigned offset, uint64_t value);

private:
  const UpdateList &getUpdates() const;

  void makeConcrete();

  void makeSymbolic();

  ref<Expr> read8(ref<Expr> offset) const;
  void write8(unsigned offset, ref<Expr> value);
  void write8(ref<Expr> offset, ref<Expr> value);

  void fastRangeCheckOffset(ref<Expr> offset, unsigned *base_r, 
                            unsigned *size_r) const;
  void flushRangeForRead(unsigned rangeBase, unsigned rangeSize) const;
  void flushRangeForWrite(unsigned rangeBase, unsigned rangeSize);

  bool isByteConcrete(unsigned offset) const;
  bool isByteFlushed(unsigned offset) const;
  bool isByteKnownSymbolic(unsigned offset) const;

  void markByteConcrete(unsigned offset);
  void markByteSymbolic(unsigned offset);
  void markByteFlushed(unsigned offset);
  void markByteUnflushed(unsigned offset);
  void setKnownSymbolic(unsigned offset, Expr *value);

  void print();
  ArrayCache *getArrayCache() const;
};
  
} // End klee namespace

#endif
