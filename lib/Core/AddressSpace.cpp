//===-- AddressSpace.cpp --------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "AddressSpace.h"
#include "CoreStats.h"
#include "Memory.h"
#include "TimingSolver.h"

#include "klee/Expr.h"
#include "klee/TimerStatIncrementer.h"

using namespace klee;

///

void AddressSpace::bindObject(const MemoryObject *mo, ObjectState *os) {
  assert(os->copyOnWriteOwner==0 && "object already has owner");
  os->copyOnWriteOwner = cowKey;
  objects = objects.replace(std::make_pair(mo, os));
}

void AddressSpace::unbindObject(const MemoryObject *mo) {
  objects = objects.remove(mo);
}

const ObjectState *AddressSpace::findObject(const MemoryObject *mo) const {
  const MemoryMap::value_type *res = objects.lookup(mo);
  
  return res ? res->second : 0;
}

ObjectState *AddressSpace::getWriteable(const MemoryObject *mo,
                                        const ObjectState *os) {
  assert(!os->readOnly);

  if (cowKey==os->copyOnWriteOwner) {
    return const_cast<ObjectState*>(os);
  } else {
    ObjectState *n = new ObjectState(*os);
    n->copyOnWriteOwner = cowKey;
    objects = objects.replace(std::make_pair(mo, n));
    return n;    
  }
}

/// 


bool AddressSpace::resolveOne(const ref<ConstantExpr> &addr, 
                              ObjectPair &result) {
  uint64_t address = addr->getZExtValue();
  MemoryObject hack(address);

  if (const MemoryMap::value_type *res = objects.lookup_previous(&hack)) {
    const MemoryObject *mo = res->first;
    // Check if the provided address is between start and end of the object
    // [mo->address, mo->address + mo->size) or the object is a 0-sized object.
    if ((mo->size==0 && address==mo->guest_address()) ||
        (address - mo->guest_address() < mo->size)) {
      result = *res;
      return true;
    }
  }

  return false;
}

bool AddressSpace::resolveOne(ExecutionState &state,
                              TimingSolver *solver,
                              const ref<ConstantExpr> &addr, 
                              ObjectPair &result) {
  uint64_t address = addr->getZExtValue();
  MemoryObject hack(address);

  if (const MemoryMap::value_type *res = objects.lookup_previous(&hack)) {
    const MemoryObject *mo = res->first;
    // Check if the provided address is between start and end of the object
    // [mo->address, mo->address + mo->size) or the object is a 0-sized object.

    if(!mo->isSizeDynamic)
      if ((mo->size==0 && address==mo->guest_address()) ||
          (address - mo->guest_address() < mo->size)) {
        result = *res;
        return true;
      }
    if(mo->isSizeDynamic)
    {
      llvm::outs() << "--> trying to resolve to a dynamic object\n";
      bool mayBeTrue;
      if (!solver->mayBeTrue(state, mo->getBoundsCheckPointer(addr), mayBeTrue))
        return false;
      if (mayBeTrue) {
        result = *res;
        return true;
      }
    }
  }
  return false;
}

bool AddressSpace::resolveOne(ExecutionState &state,
                              TimingSolver *solver,
                              ref<Expr> address,
                              ObjectPair &result,
                              bool &success) {
  if (ConstantExpr *CE = dyn_cast<ConstantExpr>(address)) {
    success = resolveOne(state, solver, CE, result);
    return true;
  } else {
    TimerStatIncrementer timer(stats::resolveTime);

    // try cheap search, will succeed for any inbounds pointer

    ref<ConstantExpr> cex;
    if (!solver->getValue(state, address, cex))
      return false;
    uint64_t example = cex->getZExtValue();
    MemoryObject hack(example);
    const MemoryMap::value_type *res = objects.lookup_previous(&hack);
    
    if (res) {
      const MemoryObject *mo = res->first;
      if(!mo->isSizeDynamic)
        if (example - mo->guest_address() < mo->size) {
          result = *res;
          success = true;
          return true;
        }
      if(mo->isSizeDynamic)
      {
        bool mayBeTrue;
        if (solver->mayBeTrue(state, mo->getBoundsCheckPointer(address), mayBeTrue) && mayBeTrue)
        {
          result = *res;
          return true;
        }
      }
    }

    // didn't work, now we have to search
       
    MemoryMap::iterator oi = objects.upper_bound(&hack);
    MemoryMap::iterator begin = objects.begin();
    MemoryMap::iterator end = objects.end();
      
    MemoryMap::iterator start = oi;
    while (oi!=begin) {
      --oi;
      const MemoryObject *mo = oi->first;
        
      bool mayBeTrue;
      if (!solver->mayBeTrue(state, 
                             mo->getBoundsCheckPointer(address), mayBeTrue))
        return false;
      if (mayBeTrue) {
        result = *oi;
        success = true;
        return true;
      } else {
        bool mustBeTrue;
        if (!solver->mustBeTrue(state, 
                                UgeExpr::create(address, mo->getBaseExpr()),
                                mustBeTrue))
          return false;
        if (mustBeTrue)
          break;
      }
    }

    // search forwards
    for (oi=start; oi!=end; ++oi) {
      const MemoryObject *mo = oi->first;

      bool mustBeTrue;
      if (!solver->mustBeTrue(state, 
                              UltExpr::create(address, mo->getBaseExpr()),
                              mustBeTrue))
        return false;
      if (mustBeTrue) {
        break;
      } else {
        bool mayBeTrue;

        if (!solver->mayBeTrue(state, 
                               mo->getBoundsCheckPointer(address),
                               mayBeTrue))
          return false;
        if (mayBeTrue) {
          result = *oi;
          success = true;
          return true;
        }
      }
    }

    success = false;
    return true;
  }
}

bool AddressSpace::resolve(ExecutionState &state,
                           TimingSolver *solver, 
                           ref<Expr> p, 
                           ResolutionList &rl, 
                           unsigned maxResolutions,
                           double timeout) {
  if (ConstantExpr *CE = dyn_cast<ConstantExpr>(p)) {
    ObjectPair res;
    if (resolveOne(CE, res))
      rl.push_back(res);
    return false;
  } else {
    TimerStatIncrementer timer(stats::resolveTime);
    uint64_t timeout_us = (uint64_t) (timeout*1000000.);

    // XXX in general this isn't exactly what we want... for
    // a multiple resolution case (or for example, a \in {b,c,0})
    // we want to find the first object, find a cex assuming
    // not the first, find a cex assuming not the second...
    // etc.
    
    // XXX how do we smartly amortize the cost of checking to
    // see if we need to keep searching up/down, in bad cases?
    // maybe we don't care?
    
    // XXX we really just need a smart place to start (although
    // if its a known solution then the code below is guaranteed
    // to hit the fast path with exactly 2 queries). we could also
    // just get this by inspection of the expr.
    
    ref<ConstantExpr> cex;
    if (!solver->getValue(state, p, cex))
      return true;
    uint64_t example = cex->getZExtValue();
    MemoryObject hack(example);
    
    MemoryMap::iterator oi = objects.upper_bound(&hack);
    MemoryMap::iterator begin = objects.begin();
    MemoryMap::iterator end = objects.end();
      
    MemoryMap::iterator start = oi;
      
    // XXX in the common case we can save one query if we ask
    // mustBeTrue before mayBeTrue for the first result. easy
    // to add I just want to have a nice symbolic test case first.
      
    // search backwards, start with one minus because this
    // is the object that p *should* be within, which means we
    // get write off the end with 4 queries (XXX can be better,
    // no?)
    while (oi!=begin) {
      --oi;
      const MemoryObject *mo = oi->first;
      if (timeout_us && timeout_us < timer.check())
        return true;

      // XXX I think there is some query wasteage here?
      ref<Expr> inBounds = mo->getBoundsCheckPointer(p);
      bool mayBeTrue;
      if (!solver->mayBeTrue(state, inBounds, mayBeTrue))
        return true;
      if (mayBeTrue) {
        rl.push_back(*oi);
        
        // fast path check
        unsigned size = rl.size();
        if (size==1) {
          bool mustBeTrue;
          if (!solver->mustBeTrue(state, inBounds, mustBeTrue))
            return true;
          if (mustBeTrue)
            return false;
        } else if (size==maxResolutions) {
          return true;
        }
      }
        
      bool mustBeTrue;
      if (!solver->mustBeTrue(state, 
                              UgeExpr::create(p, mo->getBaseExpr()),
                              mustBeTrue))
        return true;
      if (mustBeTrue)
        break;
    }
    // search forwards
    for (oi=start; oi!=end; ++oi) {
      const MemoryObject *mo = oi->first;
      if (timeout_us && timeout_us < timer.check())
        return true;

      bool mustBeTrue;
      if (!solver->mustBeTrue(state, 
                              UltExpr::create(p, mo->getBaseExpr()),
                              mustBeTrue))
        return true;
      if (mustBeTrue)
        break;
      
      // XXX I think there is some query wasteage here?
      ref<Expr> inBounds = mo->getBoundsCheckPointer(p);
      bool mayBeTrue;
      if (!solver->mayBeTrue(state, inBounds, mayBeTrue))
        return true;
      if (mayBeTrue) {
        rl.push_back(*oi);
        
        // fast path check
        unsigned size = rl.size();
        if (size==1) {
          bool mustBeTrue;
          if (!solver->mustBeTrue(state, inBounds, mustBeTrue))
            return true;
          if (mustBeTrue)
            return false;
        } else if (size==maxResolutions) {
          return true;
        }
      }
    }
  }

  return false;
}

// These two are pretty big hack so we can sort of pass memory back
// and forth to externals. They work by abusing the concrete cache
// store inside of the object states, which allows them to
// transparently avoid screwing up symbolics (if the byte is symbolic
// then its concrete cache byte isn't being used) but is just a hack.

void AddressSpace::copyOutConcretes() {
  for (MemoryMap::iterator it = objects.begin(), ie = objects.end(); 
       it != ie; ++it) {
    const MemoryObject *mo = it->first;

    if (!mo->isUserSpecified) {
      ObjectState *os = it->second;
      uint8_t *address = (uint8_t*) (unsigned long) mo->host_address();

      if (!os->readOnly)
        memcpy(address, os->concreteStore, mo->size);
    }
  }
}

bool AddressSpace::copyInConcretes() {
  for (MemoryMap::iterator it = objects.begin(), ie = objects.end(); 
       it != ie; ++it) {
    const MemoryObject *mo = it->first;

    if (!mo->isUserSpecified) {
      const ObjectState *os = it->second;
      uint8_t *address = (uint8_t*) (unsigned long) mo->host_address();

      if (memcmp(address, os->concreteStore, mo->size)!=0) {
        if (os->readOnly) {
          return false;
        } else {
          ObjectState *wos = getWriteable(mo, os);
          memcpy(wos->concreteStore, address, mo->size);
        }
      }
    }
  }

  return true;
}

/* Allocate new memory with malloc. Find a free memory chunk of size
 * <size> in the state's address space and mark it reserved.
 *
 * We first use malloc() to allocate the memory on the host (this is the
 * where we will actually store the data). We then need to map this
 * memory on the guest: we iterate over state->addressSpace.objects
 * guest_address()es and try to find a free memory region of size bigger
 * then <size> We don't differentiate between the heap and the stack: we
 * put everything into one big chunk 
 *
 * @param size Size of the new memory to allcoate
 * @param state The state Address Space of which we consider
 *
 * @return pointer to the start of available memory address on the guest
 */
 #define MEMHIGH   9223372036854775808u
 #define MEMLOW          1099511627776u
 #define CHUNKSIZE               16384u
uint64_t AddressSpace::getFreeMemchunkAtGuest() 
{
  /* Now we need to find a free memory chunk at the guest
   * Note that addressSpace.objects is a map of memory objects 
   * sorted by guest_address() (see AddressSpace.h) */
  MemoryMap::iterator obj_begin = this->objects.begin();
  MemoryMap::iterator obj_end = this->objects.end();
  uint64_t prev_begin = 0;
  uint64_t cur_end = 0;
  uint64_t prev_size = 0;
  uint64_t cur_size = 0;

  uint64_t chosen_guest_address = 0;
  bool first = false;

  /* If we don't have any objects yet, reserve space at the
   * highest memory address */
  if (obj_begin == obj_end) 
  {
    chosen_guest_address = MEMHIGH - CHUNKSIZE;
    first = true;
  }
  /* Else iterate through objects from the end: i.e from highest to lowest memory address */
  else 
  {
    const MemoryObject *obj = NULL;
    --obj_end; // Now it points to the latest object (at highest memory location)
    obj = obj_end->first;
    prev_begin = obj->guest_address();
    if(obj->isSizeDynamic) {prev_size = CHUNKSIZE;} else {prev_size = obj->size;};
    if(prev_begin + prev_size < MEMHIGH - CHUNKSIZE) return MEMHIGH - CHUNKSIZE;
    while (obj_begin != obj_end)
    {
      --obj_end; // Going from the end
      obj = obj_end->first;
      if(obj->isSizeDynamic) {cur_size = CHUNKSIZE;} else {cur_size = obj->size;};
      cur_end = obj->guest_address() + cur_size;
      if ((cur_end + CHUNKSIZE) <= prev_begin)
      {
        chosen_guest_address = prev_begin - CHUNKSIZE;
        break;
      }
      prev_begin = obj->guest_address();
    }
  }

  /* We reached the wilderness */
  if (!first && obj_begin == obj_end)
  {
    chosen_guest_address = prev_begin - CHUNKSIZE;
    assert((chosen_guest_address > MEMLOW) && "too many objects with dynamic size");
  }

  if (chosen_guest_address == 0)
    {
      llvm::outs() << "Selected guest address is 0 - this should never happen \n";
      return (0);
    }
  
  //llvm::outs() << " Found apporpriate memory chunk:  ++ [" << guest_address() << " - " << guest_address()+CHUNKSIZE << "]\n";
  return chosen_guest_address;
}

/***/

bool MemoryObjectLT::operator()(const MemoryObject *a, const MemoryObject *b) const {
  return a->guest_address() < b->guest_address();
}

