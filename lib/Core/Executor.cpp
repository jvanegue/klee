//===-- Executor.cpp ------------------------------------------------------===//
//
//                     The KLEE Symbolic Virtual Machine
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "Executor.h"
#include "Context.h"
#include "CoreStats.h"
#include "ExternalDispatcher.h"
#include "ImpliedValue.h"
#include "Memory.h"
#include "MemoryManager.h"
#include "PTree.h"
#include "Searcher.h"
#include "SeedInfo.h"
#include "SpecialFunctionHandler.h"
#include "StatsTracker.h"
#include "TimingSolver.h"
#include "UserSearcher.h"
#include "ExecutorTimerInfo.h"


#include "klee/ExecutionState.h"
#include "klee/Expr.h"
#include "klee/Interpreter.h"
#include "klee/TimerStatIncrementer.h"
#include "klee/CommandLine.h"
#include "klee/Common.h"
#include "klee/util/Assignment.h"
#include "klee/util/ExprPPrinter.h"
#include "klee/util/ExprSMTLIBPrinter.h"
#include "klee/util/ExprUtil.h"
#include "klee/util/GetElementPtrTypeIterator.h"
#include "klee/Config/Version.h"
#include "klee/Internal/ADT/KTest.h"
#include "klee/Internal/ADT/RNG.h"
#include "klee/Internal/Module/Cell.h"
#include "klee/Internal/Module/InstructionInfoTable.h"
#include "klee/Internal/Module/KInstruction.h"
#include "klee/Internal/Module/KModule.h"
#include "klee/Internal/Support/ErrorHandling.h"
#include "klee/Internal/Support/FloatEvaluation.h"
#include "klee/Internal/Support/ModuleUtil.h"
#include "klee/Internal/System/Time.h"
#include "klee/Internal/System/MemoryUsage.h"
#include "klee/SolverStats.h"

#if LLVM_VERSION_CODE >= LLVM_VERSION(3, 3)
#include "llvm/IR/Function.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/TypeBuilder.h"
#else
#include "llvm/Attributes.h"
#include "llvm/BasicBlock.h"
#include "llvm/Constants.h"
#include "llvm/Function.h"
#include "llvm/Instructions.h"
#include "llvm/IntrinsicInst.h"
#include "llvm/LLVMContext.h"
#include "llvm/Module.h"
#if LLVM_VERSION_CODE <= LLVM_VERSION(3, 1)
#include "llvm/Target/TargetData.h"
#else
#include "llvm/DataLayout.h"
#include "llvm/TypeBuilder.h"
#endif
#endif
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/ErrorHandling.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Process.h"
#include "llvm/Support/raw_ostream.h"

#if LLVM_VERSION_CODE < LLVM_VERSION(3, 5)
#include "llvm/Support/CallSite.h"
#else
#include "llvm/IR/CallSite.h"
#endif

#ifdef HAVE_ZLIB_H
#include "klee/Internal/Support/CompressionStream.h"
#endif

#include <cassert>
#include <algorithm>
#include <iomanip>
#include <iosfwd>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>

#include <sys/mman.h>

#include <errno.h>
#include <cxxabi.h>

using namespace llvm;
using namespace klee;


namespace {

  template <typename T>
  std::string ToString(T val)
  {
    std::stringstream stream;
    stream << val;
    return stream.str();
  }
  
  cl::opt<bool>
  DumpStatesOnHalt("dump-states-on-halt",
                   cl::init(true),
		   cl::desc("Dump test cases for all active states on exit (default=on)"));
  
  cl::opt<bool>
  AllowExternalSymCalls("allow-external-sym-calls",
                        cl::init(false),
			cl::desc("Allow calls with symbolic arguments to external functions.  This concretizes the symbolic arguments.  (default=off)"));

  /// The different query logging solvers that can switched on/off
  enum PrintDebugInstructionsType {
    STDERR_ALL, ///
    STDERR_SRC,
    STDERR_COMPACT,
    FILE_ALL,    ///
    FILE_SRC,    ///
    FILE_COMPACT ///
  };

  llvm::cl::list<PrintDebugInstructionsType> DebugPrintInstructions(
      "debug-print-instructions",
      llvm::cl::desc("Log instructions during execution."),
      llvm::cl::values(
          clEnumValN(STDERR_ALL, "all:stderr", "Log all instructions to stderr "
                                               "in format [src, inst_id, "
                                               "llvm_inst]"),
          clEnumValN(STDERR_SRC, "src:stderr",
                     "Log all instructions to stderr in format [src, inst_id]"),
          clEnumValN(STDERR_COMPACT, "compact:stderr",
                     "Log all instructions to stderr in format [inst_id]"),
          clEnumValN(FILE_ALL, "all:file", "Log all instructions to file "
                                           "instructions.txt in format [src, "
                                           "inst_id, llvm_inst]"),
          clEnumValN(FILE_SRC, "src:file", "Log all instructions to file "
                                           "instructions.txt in format [src, "
                                           "inst_id]"),
          clEnumValN(FILE_COMPACT, "compact:file",
                     "Log all instructions to file instructions.txt in format "
                     "[inst_id]")
          KLEE_LLVM_CL_VAL_END),
      llvm::cl::CommaSeparated);
#ifdef HAVE_ZLIB_H
  cl::opt<bool> DebugCompressInstructions(
      "debug-compress-instructions", cl::init(false),
      cl::desc("Compress the logged instructions in gzip format."));
#endif

  cl::opt<bool>
  DebugCheckForImpliedValues("debug-check-for-implied-values");


  cl::opt<bool>
  SimplifySymIndices("simplify-sym-indices",
                     cl::init(false),
		     cl::desc("Simplify symbolic accesses using equalities from other constraints (default=off)"));

  cl::opt<bool>
  EqualitySubstitution("equality-substitution",
		       cl::init(true),
		       cl::desc("Simplify equality expressions before querying the solver (default=on)."));

  cl::opt<unsigned>
  MaxSymArraySize("max-sym-array-size",
                  cl::init(0));

  cl::opt<bool>
  SuppressExternalWarnings("suppress-external-warnings",
			   cl::init(false),
			   cl::desc("Supress warnings about calling external functions."));

  cl::opt<bool>
  AllExternalWarnings("all-external-warnings",
		      cl::init(false),
		      cl::desc("Issue an warning everytime an external call is made," 
			       "as opposed to once per function (default=off)"));

  cl::opt<bool>
  OnlyOutputStatesCoveringNew("only-output-states-covering-new",
                              cl::init(false),
			      cl::desc("Only output test cases covering new code (default=off)."));

  cl::opt<bool>
  EmitAllErrors("emit-all-errors",
                cl::init(false),
                cl::desc("Generate tests cases for all errors "
                         "(default=off, i.e. one per (error,instruction) pair)"));
  
  cl::opt<bool>
  NoExternals("no-externals", 
           cl::desc("Do not allow external function calls (default=off)"));

  cl::opt<bool>
  AlwaysOutputSeeds("always-output-seeds",
		    cl::init(true));

  cl::opt<bool>
  OnlyReplaySeeds("only-replay-seeds",
		  cl::init(false),
                  cl::desc("Discard states that do not have a seed (default=off)."));
 
  cl::opt<bool>
  OnlySeed("only-seed",
	   cl::init(false),
           cl::desc("Stop execution after seeding is done without doing regular search (default=off)."));
 
  cl::opt<bool>
  AllowSeedExtension("allow-seed-extension",
		     cl::init(false),
                     cl::desc("Allow extra (unbound) values to become symbolic during seeding (default=false)."));
 
  cl::opt<bool>
  ZeroSeedExtension("zero-seed-extension",
		    cl::init(false),
		    cl::desc("(default=off)"));
 
  cl::opt<bool>
  AllowSeedTruncation("allow-seed-truncation",
		      cl::init(false),
                      cl::desc("Allow smaller buffers than in seeds (default=off)."));
 
  cl::opt<bool>
  NamedSeedMatching("named-seed-matching",
		    cl::init(false),
                    cl::desc("Use names to match symbolic objects to inputs (default=off)."));

  cl::opt<double>
  MaxStaticForkPct("max-static-fork-pct", 
		   cl::init(1.),
		   cl::desc("(default=1.0)"));

  cl::opt<double>
  MaxStaticSolvePct("max-static-solve-pct",
		    cl::init(1.),
		    cl::desc("(default=1.0)"));

  cl::opt<double>
  MaxStaticCPForkPct("max-static-cpfork-pct", 
		     cl::init(1.),
		     cl::desc("(default=1.0)"));

  cl::opt<double>
  MaxStaticCPSolvePct("max-static-cpsolve-pct",
		      cl::init(1.),
		      cl::desc("(default=1.0)"));

  cl::opt<double>
  MaxInstructionTime("max-instruction-time",
                     cl::desc("Only allow a single instruction to take this much time (default=0s (off)). Enables --use-forked-solver"),
                     cl::init(0));
  
  cl::opt<double>
  SeedTime("seed-time",
           cl::desc("Amount of time to dedicate to seeds, before normal search (default=0 (off))"),
           cl::init(0));
  
  cl::list<Executor::TerminateReason>
  ExitOnErrorType("exit-on-error-type",
		  cl::desc("Stop execution after reaching a specified condition.  (default=off)"),
		  cl::values(
		    clEnumValN(Executor::Abort, "Abort", "The program crashed"),
		    clEnumValN(Executor::Assert, "Assert", "An assertion was hit"),
		    clEnumValN(Executor::Exec, "Exec", "Trying to execute an unexpected instruction"),
		    clEnumValN(Executor::External, "External", "External objects referenced"),
		    clEnumValN(Executor::Free, "Free", "Freeing invalid memory"),
		    clEnumValN(Executor::Model, "Model", "Memory model limit hit"),
		    clEnumValN(Executor::Overflow, "Overflow", "An overflow occurred"),
		    clEnumValN(Executor::Ptr, "Ptr", "Pointer error"),
		    clEnumValN(Executor::ReadOnly, "ReadOnly", "Write to read-only memory"),
		    clEnumValN(Executor::ReportError, "ReportError", "klee_report_error called"),
		    clEnumValN(Executor::User, "User", "Wrong klee_* functions invocation"),
		    clEnumValN(Executor::Unhandled, "Unhandled", "Unhandled instruction hit")
		    KLEE_LLVM_CL_VAL_END),
		  cl::ZeroOrMore);

#if LLVM_VERSION_CODE < LLVM_VERSION(3, 0)
  cl::opt<unsigned int>
  StopAfterNInstructions("stop-after-n-instructions",
                         cl::desc("Stop execution after specified number of instructions (default=0 (off))"),
                         cl::init(0));
#else
  cl::opt<unsigned long long>
  StopAfterNInstructions("stop-after-n-instructions",
                         cl::desc("Stop execution after specified number of instructions (default=0 (off))"),
                         cl::init(0));
#endif
  
  cl::opt<unsigned>
  MaxForks("max-forks",
           cl::desc("Only fork this many times (default=-1 (off))"),
           cl::init(~0u));
  
  cl::opt<unsigned>
  MaxDepth("max-depth",
           cl::desc("Only allow this many symbolic branches (default=0 (off))"),
           cl::init(0));
  
  cl::opt<unsigned>
  MaxMemory("max-memory",
            cl::desc("Refuse to fork when above this amount of memory (in MB, default=2000)"),
            cl::init(2000));

  cl::opt<bool>
  MaxMemoryInhibit("max-memory-inhibit",
            cl::desc("Inhibit forking at memory cap (vs. random terminate) (default=on)"),
            cl::init(true));

  cl::opt<bool>
  SymStubs("symbolic-stubs",
            cl::desc("Enable symbolic propagation through stubs (like strlen or atoi) default = on"),
            cl::init(true));

  cl::opt<bool>
  TrackEdges("track-edges",
            cl::desc("Track Control Flow Edges and Symbolic State edges as they are visited. "),
            cl::init(false));
}


namespace klee {
  RNG theRNG;
}

const char *Executor::TerminateReasonNames[] = {
  [ Abort ] = "abort",
  [ Assert ] = "assert",
  [ Exec ] = "exec",
  [ External ] = "external",
  [ Free ] = "free",
  [ Model ] = "model",
  [ Overflow ] = "overflow",
  [ Ptr ] = "ptr",
  [ ReadOnly ] = "readonly",
  [ ReportError ] = "reporterror",
  [ User ] = "user",
  [ Unhandled ] = "xxx",
};


/* HKLEE: Defining a list of symbolic stubs that will propagate symbolicness by default */
void	Executor::SymbolicStubsRegister() {
  symStubs["atoi"] = 1;
  symStubs["strlen"] = 1;
  symStubs["rand"] = 0;
}


Executor::Executor(LLVMContext &ctx, const InterpreterOptions &opts,
    InterpreterHandler *ih)
    : Interpreter(opts), kmodule(0), interpreterHandler(ih), searcher(0),
      externalDispatcher(new ExternalDispatcher(ctx)), statsTracker(0),
      pathWriter(0), symPathWriter(0), specialFunctionHandler(0),
      processTree(0),

      next_state_id(1),

      replayKTest(0), replayPath(0), usingSeeds(0),
      atMemoryLimit(false), inhibitForking(false), haltExecution(false),
      ivcEnabled(false),
      coreSolverTimeout(MaxCoreSolverTime != 0 && MaxInstructionTime != 0
                            ? std::min(MaxCoreSolverTime, MaxInstructionTime)
                            : std::max(MaxCoreSolverTime, MaxInstructionTime)),
      debugInstFile(0), debugHeapFile(0), debugLogBuffer(debugBufferString) {

  if (coreSolverTimeout) UseForkedCoreSolver = true;
  Solver *coreSolver = klee::createCoreSolver(CoreSolverToUse);
  if (!coreSolver) {
    klee_error("Failed to create core solver\n");
  }

  Solver *solver = constructSolverChain(
      coreSolver,
      interpreterHandler->getOutputFilename(ALL_QUERIES_SMT2_FILE_NAME),
      interpreterHandler->getOutputFilename(SOLVER_QUERIES_SMT2_FILE_NAME),
      interpreterHandler->getOutputFilename(ALL_QUERIES_KQUERY_FILE_NAME),
      interpreterHandler->getOutputFilename(SOLVER_QUERIES_KQUERY_FILE_NAME));

  this->solver = new TimingSolver(solver, EqualitySubstitution);
  memory = new MemoryManager(&arrayCache);

  //if (optionIsSet(DebugPrintInstructions, FILE_ALL) ||
  //  optionIsSet(DebugPrintInstructions, FILE_COMPACT) ||
  //  optionIsSet(DebugPrintInstructions, FILE_SRC)) {
    std::string debug_file_name =
      interpreterHandler->getOutputFilename("instructions.txt");
    std::string heap_debug_file_name =
      interpreterHandler->getOutputFilename("heapdebug.txt");
    
    std::string ErrorInfo;
#ifdef HAVE_ZLIB_H
    if (!DebugCompressInstructions) {
#endif

#if LLVM_VERSION_CODE >= LLVM_VERSION(3, 6)
    std::error_code ec;
    debugInstFile = new llvm::raw_fd_ostream(debug_file_name.c_str(), ec,
                                             llvm::sys::fs::OpenFlags::F_Text);
    if (ec)
	    ErrorInfo = ec.message();
#elif LLVM_VERSION_CODE >= LLVM_VERSION(3, 5)
    debugInstFile = new llvm::raw_fd_ostream(debug_file_name.c_str(), ErrorInfo,
                                             llvm::sys::fs::OpenFlags::F_Text);
    debugHeapFile = new llvm::raw_fd_ostream(heap_debug_file_name.c_str(), ErrorInfo,
                                             llvm::sys::fs::OpenFlags::F_Text);

#else
    debugInstFile =
        new llvm::raw_fd_ostream(debug_file_name.c_str(), ErrorInfo);
    debugHeapFile =
      new llvm::raw_fd_ostream(heap_debug_file_name.c_str(), ErrorInfo);
    
#endif
#ifdef HAVE_ZLIB_H
    } else {
      debugInstFile = new compressed_fd_ostream((debug_file_name + ".gz").c_str(), ErrorInfo);
      debugHeapFile = new compressed_fd_ostream((heap_debug_file_name + ".gz").c_str(), ErrorInfo);
    }
#endif
    if (ErrorInfo != "") {
      klee_error("Could not open file %s : %s", debug_file_name.c_str(),
                 ErrorInfo.c_str());
    }

    SymbolicStubsRegister();    
}


const Module *Executor::setModule(llvm::Module *module, 
                                  const ModuleOptions &opts) {
  assert(!kmodule && module && "can only register one module"); // XXX gross
  
  kmodule = new KModule(module);

  // Initialize the context.
#if LLVM_VERSION_CODE <= LLVM_VERSION(3, 1)
  TargetData *TD = kmodule->targetData;
#else
  DataLayout *TD = kmodule->targetData;
#endif
  Context::initialize(TD->isLittleEndian(),
                      (Expr::Width) TD->getPointerSizeInBits());

  specialFunctionHandler = new SpecialFunctionHandler(*this);

  specialFunctionHandler->prepare();
  kmodule->prepare(opts, interpreterHandler);
  specialFunctionHandler->bind();

  if (StatsTracker::useStatistics() || userSearcherRequiresMD2U()) {
    statsTracker = 
      new StatsTracker(*this,
                       interpreterHandler->getOutputFilename("assembly.ll"),
                       userSearcherRequiresMD2U());
  }
  
  return module;
}

Executor::~Executor() {
  delete memory;
  delete externalDispatcher;
  if (processTree)
    delete processTree;
  if (specialFunctionHandler)
    delete specialFunctionHandler;
  if (statsTracker)
    delete statsTracker;
  delete solver;
  delete kmodule;
  while(!timers.empty()) {
    delete timers.back();
    timers.pop_back();
  }
  if (debugInstFile) {
    delete debugInstFile;
  }
  
  if (TrackEdges) {
    doDumpEdges();
  }

  if (debugHeapFile) {
    delete debugHeapFile;
  }
}


/*** JV: Added in Heap-KLEE to track the heap state independently of the entire state space ***/
void	Executor::doDumpEdges()
{
  (*debugHeapFile) << "Now dumping output graphs... \n";
  
  // Control Flow Graph
  llvm::raw_fd_ostream *fd = interpreterHandler->openOutputFile("hklee-cfg.gv");
  assert(fd && "Unable to open cfg graphviz file");
  fd->seek(0);
  *fd << "digraph cfg { \n\n";	    
  *fd << "node [shape=box]; ";  
  for (NodeMap::iterator it = ControlStates.begin(); it != ControlStates.end(); it++)
    *fd << it->first << "; ";
  *fd << "\n\n";
  for (EdgeMap::iterator it = ControlEdges.begin(); it != ControlEdges.end(); it++)
    {
      StringPair pair = it->first;
      *fd << " " << pair.first << " -> " << pair.second << ";\n";
    }
  *fd << "\n";
  *fd << "overlap=false \n";
  *fd << "label=\"Control Flow Graph\" \n";
  *fd << "} \n ";
  fd->flush();
  delete fd;
  
  // State Space Graph
  llvm::raw_fd_ostream *fd2 = interpreterHandler->openOutputFile("hklee-ss.gv");
  assert(fd2 && "Unable to open ss graphviz file");
  fd2->seek(0);      
  *fd2 << "digraph ss { \n\n";
  *fd2 << "size=\"7,10\" \n";
  *fd2 << "node [width=.25,height=.375,fontsize=9]; \n";  
  for (NodeMap::iterator it = SymStates.begin(); it != SymStates.end(); it++)
    *fd2 << it->first << "; ";
  *fd2 << "\n\n";
  for (EdgeMap::iterator it = SymEdges.begin(); it != SymEdges.end(); it++)
    {
      StringPair pair = it->first;
      *fd2 << " " << pair.first << " -> " << pair.second << ";\n";
    }
  *fd2 << "\n";
  *fd2 << "overlap=false \n";
  *fd2 << "label=\"Full State Space \" \n";
  *fd2 << "} \n ";
  fd2->flush();
  delete fd2;
  
  // Heap State Graph
  llvm::raw_fd_ostream *fd3 = interpreterHandler->openOutputFile("hklee-heap.gv");
  assert(fd3 && "Unable to open heap graphviz file");
  fd3->seek(0);
  *fd3 << "digraph heap { \n\n";	    
  for (NodeMap::iterator it = HeapStates.begin(); it != HeapStates.end(); it++)
    {
      StateDesc& desc = it->second;
      std::string color = (desc.first ? "style=filled,fillcolor=red," : "");
      *fd3 << it->first << " [label=\"" << desc.second << "\", " + color + "shape=rectangle]; \n";
    }
  *fd3 << "\n\n";
  for (EdgeMap::iterator it = HeapEdges.begin(); it != HeapEdges.end(); it++)
    {
      StringPair pair = it->first;
      std::string label = it->second;
      *fd2 << " " << pair.first << " -> " << pair.second << " [label=\"" << label << "\"];\n";
    }
  *fd3 << "\n";
  *fd3 << "overlap=false \n";
  *fd3 << "label=\"Heap State Space\" \n";
  *fd3 << "} \n ";
  fd3->flush();
  delete fd3;
  
  (*debugHeapFile) << "Finished dumping output graphs... \n";
}

/*** JV: When we encounter a violation, make sure the violation state is part of the output graph for visualiation ****/
void Executor::doDumpViolationState(ExecutionState& state, std::string label)
{
  std::string orig_state_name  = ToString(state.last_heap_state_id);
  std::string state_name  = ToString(state.id);
  std::string state_parent = state.parentFunction();

  std::string local_objnum = ToString(state.addressSpace.local_obj_nbr);
  std::string global_objnum = ToString(state.addressSpace.global_obj_nbr);
  std::string fixed_objnum = ToString(state.addressSpace.fixed_obj_nbr);
  std::string sym_objnum = ToString(state.addressSpace.symbolic_obj_nbr);
  std::string total_objnum = ToString(state.ObjectNbr());
  std::string state_objnum = "(" + total_objnum + "=(" + global_objnum + "G,"
    + local_objnum + "L)," + sym_objnum + "S," + fixed_objnum + "F)";
  
  std::string state_constnum = ToString(state.constraints.size()) + "C";
  std::string state_label = state_parent + "," + state_objnum + "," + state_constnum;
  HeapStates[state_name] = std::make_pair(true,state_label);
  
  StringPair fpair = std::make_pair(orig_state_name, state_name);
  if (HeapEdges.count(fpair) == 0)
    HeapEdges[fpair] = label;

  (*debugHeapFile) << "\n **** NOW PRINTING CONSTRAINTS AT VIOLATON STATE:\n";
  state.constraints.print(*debugHeapFile);
  (*debugHeapFile) << "\n **** END PRINTING CONSTRAINTS AT VIOLATON STATE\n";
}



/***/

void Executor::initializeGlobalObject(ExecutionState &state, ObjectState *os,
                                      const Constant *c, 
                                      unsigned offset) {
#if LLVM_VERSION_CODE <= LLVM_VERSION(3, 1)
  TargetData *targetData = kmodule->targetData;
#else
  DataLayout *targetData = kmodule->targetData;
#endif
  if (const ConstantVector *cp = dyn_cast<ConstantVector>(c)) {
    unsigned elementSize =
      targetData->getTypeStoreSize(cp->getType()->getElementType());
    for (unsigned i=0, e=cp->getNumOperands(); i != e; ++i)
      initializeGlobalObject(state, os, cp->getOperand(i), 
			     offset + i*elementSize);
  } else if (isa<ConstantAggregateZero>(c)) {
    unsigned i, size = targetData->getTypeStoreSize(c->getType());
    for (i=0; i<size; i++)
      os->write8(offset+i, (uint8_t) 0);
  } else if (const ConstantArray *ca = dyn_cast<ConstantArray>(c)) {
    unsigned elementSize =
      targetData->getTypeStoreSize(ca->getType()->getElementType());
    for (unsigned i=0, e=ca->getNumOperands(); i != e; ++i)
      initializeGlobalObject(state, os, ca->getOperand(i), 
			     offset + i*elementSize);
  } else if (const ConstantStruct *cs = dyn_cast<ConstantStruct>(c)) {
    const StructLayout *sl =
      targetData->getStructLayout(cast<StructType>(cs->getType()));
    for (unsigned i=0, e=cs->getNumOperands(); i != e; ++i)
      initializeGlobalObject(state, os, cs->getOperand(i), 
			     offset + sl->getElementOffset(i));
#if LLVM_VERSION_CODE >= LLVM_VERSION(3, 1)
  } else if (const ConstantDataSequential *cds =
               dyn_cast<ConstantDataSequential>(c)) {
    unsigned elementSize =
      targetData->getTypeStoreSize(cds->getElementType());
    for (unsigned i=0, e=cds->getNumElements(); i != e; ++i)
      initializeGlobalObject(state, os, cds->getElementAsConstant(i),
                             offset + i*elementSize);
#endif
  } else if (!isa<UndefValue>(c)) {
    unsigned StoreBits = targetData->getTypeStoreSizeInBits(c->getType());
    ref<ConstantExpr> C = evalConstant(c);

    // Extend the constant if necessary;
    assert(StoreBits >= C->getWidth() && "Invalid store size!");
    if (StoreBits > C->getWidth())
      C = C->ZExt(StoreBits);

    os->write(offset, C);
  }
}

MemoryObject * Executor::addExternalObject(ExecutionState &state, 
                                           void *addr, unsigned size, 
                                           bool isReadOnly) {
  MemoryObject *mo = memory->allocateFixed((uint64_t) (unsigned long) addr, 
                                           size, 0);
  ObjectState *os = bindObjectInState(state, mo, false);
  for(unsigned i = 0; i < size; i++)
    os->write8(i, ((uint8_t*)addr)[i]);
  if(isReadOnly)
    os->setReadOnly(true);  
  return mo;
}


extern void *__dso_handle __attribute__ ((__weak__));

void Executor::initializeGlobals(ExecutionState &state) {
  Module *m = kmodule->module;

  if (m->getModuleInlineAsm() != "")
    klee_warning("executable has module level assembly (ignoring)");
#if LLVM_VERSION_CODE < LLVM_VERSION(3, 3)
  assert(m->lib_begin() == m->lib_end() &&
         "XXX do not support dependent libraries");
#endif
  // represent function globals using the address of the actual llvm function
  // object. given that we use malloc to allocate memory in states this also
  // ensures that we won't conflict. we don't need to allocate a memory object
  // since reading/writing via a function pointer is unsupported anyway.
  for (Module::iterator i = m->begin(), ie = m->end(); i != ie; ++i) {
    Function *f = static_cast<Function *>(i);
    ref<ConstantExpr> addr(0);

    // If the symbol has external weak linkage then it is implicitly
    // not defined in this module; if it isn't resolvable then it
    // should be null.
    if (f->hasExternalWeakLinkage() && 
        !externalDispatcher->resolveSymbol(f->getName())) {
      addr = Expr::createPointer(0);
    } else {
      addr = Expr::createPointer((unsigned long) (void*) f);
      legalFunctions.insert((uint64_t) (unsigned long) (void*) f);
    }
    
    globalAddresses.insert(std::make_pair(f, addr));
  }

  // Disabled, we don't want to promote use of live externals.
#ifdef HAVE_CTYPE_EXTERNALS
#ifndef WINDOWS
#ifndef DARWIN
  /* From /usr/include/errno.h: it [errno] is a per-thread variable. */
  int *errno_addr = __errno_location();
  addExternalObject(state, (void *)errno_addr, sizeof *errno_addr, false);

  /* from /usr/include/ctype.h:
       These point into arrays of 384, so they can be indexed by any `unsigned
       char' value [0,255]; by EOF (-1); or by any `signed char' value
       [-128,-1).  ISO C requires that the ctype functions work for `unsigned */
  const uint16_t **addr = __ctype_b_loc();
  addExternalObject(state, const_cast<uint16_t*>(*addr-128),
                    384 * sizeof **addr, true);
  addExternalObject(state, addr, sizeof(*addr), true);
    
  const int32_t **lower_addr = __ctype_tolower_loc();
  addExternalObject(state, const_cast<int32_t*>(*lower_addr-128),
                    384 * sizeof **lower_addr, true);
  addExternalObject(state, lower_addr, sizeof(*lower_addr), true);
  
  const int32_t **upper_addr = __ctype_toupper_loc();
  addExternalObject(state, const_cast<int32_t*>(*upper_addr-128),
                    384 * sizeof **upper_addr, true);
  addExternalObject(state, upper_addr, sizeof(*upper_addr), true);
#endif
#endif
#endif

  // allocate and initialize globals, done in two passes since we may
  // need address of a global in order to initialize some other one.

  // allocate memory objects for all globals
  for (Module::const_global_iterator i = m->global_begin(),
         e = m->global_end();
       i != e; ++i) {
    const GlobalVariable *v = static_cast<const GlobalVariable *>(i);
    size_t globalObjectAlignment = getAllocationAlignment(v);
    if (i->isDeclaration()) {
      // FIXME: We have no general way of handling unknown external
      // symbols. If we really cared about making external stuff work
      // better we could support user definition, or use the EXE style
      // hack where we check the object file information.

      LLVM_TYPE_Q Type *ty = i->getType()->getElementType();
      uint64_t size = 0;
      if (ty->isSized()) {
	size = kmodule->targetData->getTypeStoreSize(ty);
      } else {
        klee_warning("Type for %.*s is not sized", (int)i->getName().size(),
			i->getName().data());
      }

      // XXX - DWD - hardcode some things until we decide how to fix.
#ifndef WINDOWS
      if (i->getName() == "_ZTVN10__cxxabiv117__class_type_infoE") {
        size = 0x2C;
      } else if (i->getName() == "_ZTVN10__cxxabiv120__si_class_type_infoE") {
        size = 0x2C;
      } else if (i->getName() == "_ZTVN10__cxxabiv121__vmi_class_type_infoE") {
        size = 0x2C;
      }
#endif

      if (size == 0) {
        klee_warning("Unable to find size for global variable: %.*s (use will result in out of bounds access)",
			(int)i->getName().size(), i->getName().data());
      }

      MemoryObject *mo = memory->allocate(size, /*isLocal=*/false,
                                          /*isGlobal=*/true, /*allocSite=*/v,
                                          /*alignment=*/globalObjectAlignment);
      ObjectState *os = bindObjectInState(state, mo, false);
      globalObjects.insert(std::make_pair(v, mo));
      globalAddresses.insert(std::make_pair(v, mo->getBaseExpr()));

      // Program already running = object already initialized.  Read
      // concrete value and write it to our copy.
      if (size) {
        void *addr;
        if (i->getName() == "__dso_handle") {
          addr = &__dso_handle; // wtf ?
        } else {
          addr = externalDispatcher->resolveSymbol(i->getName());
        }
        if (!addr)
          klee_error("unable to load symbol(%s) while initializing globals.", 
                     i->getName().data());

        for (unsigned offset=0; offset<mo->size; offset++)
          os->write8(offset, ((unsigned char*)addr)[offset]);
      }
    } else {
      LLVM_TYPE_Q Type *ty = i->getType()->getElementType();
      uint64_t size = kmodule->targetData->getTypeStoreSize(ty);
      MemoryObject *mo = memory->allocate(size, /*isLocal=*/false,
                                          /*isGlobal=*/true, /*allocSite=*/v,
                                          /*alignment=*/globalObjectAlignment);
      if (!mo)
        llvm::report_fatal_error("out of memory");
      ObjectState *os = bindObjectInState(state, mo, false);
      globalObjects.insert(std::make_pair(v, mo));
      globalAddresses.insert(std::make_pair(v, mo->getBaseExpr()));

      if (!i->hasInitializer())
          os->initializeToRandom();
    }
  }
  
  // link aliases to their definitions (if bound)
  for (Module::alias_iterator i = m->alias_begin(), ie = m->alias_end(); 
       i != ie; ++i) {
    // Map the alias to its aliasee's address. This works because we have
    // addresses for everything, even undefined functions. 
    globalAddresses.insert(std::make_pair(static_cast<GlobalAlias *>(i),
	  evalConstant(i->getAliasee())));
  }

  // once all objects are allocated, do the actual initialization
  for (Module::const_global_iterator i = m->global_begin(),
         e = m->global_end();
       i != e; ++i) {
    if (i->hasInitializer()) {
      const GlobalVariable *v = static_cast<const GlobalVariable *>(i);
      MemoryObject *mo = globalObjects.find(v)->second;
      const ObjectState *os = state.addressSpace.findObject(mo);
      assert(os);
      ObjectState *wos = state.addressSpace.getWriteable(mo, os);
      
      initializeGlobalObject(state, wos, i->getInitializer(), 0);
      // if(i->isConstant()) os->setReadOnly(true);
    }
  }
}

void Executor::branch(ExecutionState &state, 
                      const std::vector< ref<Expr> > &conditions,
                      std::vector<ExecutionState*> &result) {
  TimerStatIncrementer timer(stats::forkTime);
  unsigned N = conditions.size();
  assert(N);

  if (MaxForks!=~0u && stats::forks >= MaxForks) {
    unsigned next = theRNG.getInt32() % N;
    for (unsigned i=0; i<N; ++i) {
      if (i == next) {
        result.push_back(&state);
      } else {
        result.push_back(NULL);
      }
    }
  } else {
    stats::forks += N-1;

    // XXX do proper balance or keep random?
    result.push_back(&state);
    for (unsigned i=1; i<N; ++i) {
      ExecutionState *es = result[theRNG.getInt32() % i];
      ExecutionState *ns = es->branch();

      // JV: Add this to track number of state space branching
      statsTracker->incNumFork();
      
      // JV: Add these two states in the symbolic edges
      this->trackEdges(*es, *ns, EDGE_SYM, "branch");
      
      addedStates.push_back(ns);
      result.push_back(ns);
      es->ptreeNode->data = 0;
      std::pair<PTree::Node*,PTree::Node*> res = 
        processTree->split(es->ptreeNode, ns, es);
      ns->ptreeNode = res.first;
      es->ptreeNode = res.second;
    }
  }

  // If necessary redistribute seeds to match conditions, killing
  // states if necessary due to OnlyReplaySeeds (inefficient but
  // simple).
  
  std::map< ExecutionState*, std::vector<SeedInfo> >::iterator it = 
    seedMap.find(&state);
  if (it != seedMap.end()) {
    std::vector<SeedInfo> seeds = it->second;
    seedMap.erase(it);

    // Assume each seed only satisfies one condition (necessarily true
    // when conditions are mutually exclusive and their conjunction is
    // a tautology).
    for (std::vector<SeedInfo>::iterator siit = seeds.begin(), 
           siie = seeds.end(); siit != siie; ++siit) {
      unsigned i;
      for (i=0; i<N; ++i) {
        ref<ConstantExpr> res;
        bool success = 
          solver->getValue(state, siit->assignment.evaluate(conditions[i]), 
                           res);
        assert(success && "FIXME: Unhandled solver failure");
        (void) success;
        if (res->isTrue())
          break;
      }
      
      // If we didn't find a satisfying condition randomly pick one
      // (the seed will be patched).
      if (i==N)
        i = theRNG.getInt32() % N;

      // Extra check in case we're replaying seeds with a max-fork
      if (result[i])
        seedMap[result[i]].push_back(*siit);
    }

    if (OnlyReplaySeeds) {
      for (unsigned i=0; i<N; ++i) {
        if (result[i] && !seedMap.count(result[i])) {
          terminateState(*result[i]);
          result[i] = NULL;
        }
      } 
    }
  }

  for (unsigned i=0; i<N; ++i)
    if (result[i])
      addConstraint(*result[i], conditions[i]);
}

Executor::StatePair 
Executor::fork(ExecutionState &current, ref<Expr> condition, bool isInternal) {
  Solver::Validity res;
  std::map< ExecutionState*, std::vector<SeedInfo> >::iterator it = 
    seedMap.find(&current);
  bool isSeeding = it != seedMap.end();

  if (!isSeeding && !isa<ConstantExpr>(condition) && 
      (MaxStaticForkPct!=1. || MaxStaticSolvePct != 1. ||
       MaxStaticCPForkPct!=1. || MaxStaticCPSolvePct != 1.) &&
      statsTracker->elapsed() > 60.) {
    StatisticManager &sm = *theStatisticManager;
    CallPathNode *cpn = current.stack.back().callPathNode;
    if ((MaxStaticForkPct<1. &&
         sm.getIndexedValue(stats::forks, sm.getIndex()) > 
         stats::forks*MaxStaticForkPct) ||
        (MaxStaticCPForkPct<1. &&
         cpn && (cpn->statistics.getValue(stats::forks) > 
                 stats::forks*MaxStaticCPForkPct)) ||
        (MaxStaticSolvePct<1 &&
         sm.getIndexedValue(stats::solverTime, sm.getIndex()) > 
         stats::solverTime*MaxStaticSolvePct) ||
        (MaxStaticCPForkPct<1. &&
         cpn && (cpn->statistics.getValue(stats::solverTime) > 
                 stats::solverTime*MaxStaticCPSolvePct))) {
      ref<ConstantExpr> value; 
      bool success = solver->getValue(current, condition, value);
      assert(success && "FIXME: Unhandled solver failure");
      (void) success;
      addConstraint(current, EqExpr::create(value, condition));
      condition = value;
    }
  }

  double timeout = coreSolverTimeout;
  if (isSeeding)
    timeout *= it->second.size();
  solver->setTimeout(timeout);
  bool success = solver->evaluate(current, condition, res);
  solver->setTimeout(0);
  if (!success) {
    current.pc = current.prevPC;
    terminateStateEarly(current, "Query timed out (fork).");
    return StatePair(0, 0);
  }

  if (!isSeeding) {
    if (replayPath && !isInternal) {
      assert(replayPosition<replayPath->size() &&
             "ran out of branches in replay path mode");
      bool branch = (*replayPath)[replayPosition++];
      
      if (res==Solver::True) {
        assert(branch && "hit invalid branch in replay path mode");
      } else if (res==Solver::False) {
        assert(!branch && "hit invalid branch in replay path mode");
      } else {
        // add constraints
        if(branch) {
          res = Solver::True;
          addConstraint(current, condition);
        } else  {
          res = Solver::False;
          addConstraint(current, Expr::createIsZero(condition));
        }
      }
    } else if (res==Solver::Unknown) {
      assert(!replayKTest && "in replay mode, only one branch can be true.");
      
      if ((MaxMemoryInhibit && atMemoryLimit) || 
          current.forkDisabled ||
          inhibitForking || 
          (MaxForks!=~0u && stats::forks >= MaxForks)) {

	if (MaxMemoryInhibit && atMemoryLimit)
	  klee_warning_once(0, "skipping fork (memory cap exceeded)");
	else if (current.forkDisabled)
	  klee_warning_once(0, "skipping fork (fork disabled on current path)");
	else if (inhibitForking)
	  klee_warning_once(0, "skipping fork (fork disabled globally)");
	else 
	  klee_warning_once(0, "skipping fork (max-forks reached)");

        TimerStatIncrementer timer(stats::forkTime);
        if (theRNG.getBool()) {
          addConstraint(current, condition);
          res = Solver::True;        
        } else {
          addConstraint(current, Expr::createIsZero(condition));
          res = Solver::False;
        }
      }
    }
  }

  // Fix branch in only-replay-seed mode, if we don't have both true
  // and false seeds.
  if (isSeeding && 
      (current.forkDisabled || OnlyReplaySeeds) && 
      res == Solver::Unknown) {
    bool trueSeed=false, falseSeed=false;
    // Is seed extension still ok here?
    for (std::vector<SeedInfo>::iterator siit = it->second.begin(), 
           siie = it->second.end(); siit != siie; ++siit) {
      ref<ConstantExpr> res;
      bool success = 
        solver->getValue(current, siit->assignment.evaluate(condition), res);
      assert(success && "FIXME: Unhandled solver failure");
      (void) success;
      if (res->isTrue()) {
        trueSeed = true;
      } else {
        falseSeed = true;
      }
      if (trueSeed && falseSeed)
        break;
    }
    if (!(trueSeed && falseSeed)) {
      assert(trueSeed || falseSeed);
      
      res = trueSeed ? Solver::True : Solver::False;
      addConstraint(current, trueSeed ? condition : Expr::createIsZero(condition));
    }
  }


  // XXX - even if the constraint is provable one way or the other we
  // can probably benefit by adding this constraint and allowing it to
  // reduce the other constraints. For example, if we do a binary
  // search on a particular value, and then see a comparison against
  // the value it has been fixed at, we should take this as a nice
  // hint to just use the single constraint instead of all the binary
  // search ones. If that makes sense.
  if (res==Solver::True) {
    if (!isInternal) {
      if (pathWriter) {
        current.pathOS << "1";
      }
    }

    return StatePair(&current, 0);
  } else if (res==Solver::False) {
    if (!isInternal) {
      if (pathWriter) {
        current.pathOS << "0";
      }
    }

    return StatePair(0, &current);
  } else {
    TimerStatIncrementer timer(stats::forkTime);
    ExecutionState *falseState, *trueState = &current;

    ++stats::forks;

    falseState = trueState->branch();

    // JV: added
    statsTracker->incNumFork();
    
    addedStates.push_back(falseState);

    if (it != seedMap.end()) {
      std::vector<SeedInfo> seeds = it->second;
      it->second.clear();
      std::vector<SeedInfo> &trueSeeds = seedMap[trueState];
      std::vector<SeedInfo> &falseSeeds = seedMap[falseState];
      for (std::vector<SeedInfo>::iterator siit = seeds.begin(), 
             siie = seeds.end(); siit != siie; ++siit) {
        ref<ConstantExpr> res;
        bool success = 
          solver->getValue(current, siit->assignment.evaluate(condition), res);
        assert(success && "FIXME: Unhandled solver failure");
        (void) success;
        if (res->isTrue()) {
          trueSeeds.push_back(*siit);
        } else {
          falseSeeds.push_back(*siit);
        }
      }
      
      bool swapInfo = false;
      if (trueSeeds.empty()) {
        if (&current == trueState) swapInfo = true;
        seedMap.erase(trueState);
      }
      if (falseSeeds.empty()) {
        if (&current == falseState) swapInfo = true;
        seedMap.erase(falseState);
      }
      if (swapInfo) {
        std::swap(trueState->coveredNew, falseState->coveredNew);
        std::swap(trueState->coveredLines, falseState->coveredLines);
      }
    }

    current.ptreeNode->data = 0;
    std::pair<PTree::Node*, PTree::Node*> res =
      processTree->split(current.ptreeNode, falseState, trueState);
    falseState->ptreeNode = res.first;
    trueState->ptreeNode = res.second;

    if (pathWriter) {
      // Need to update the pathOS.id field of falseState, otherwise the same id
      // is used for both falseState and trueState.
      falseState->pathOS = pathWriter->open(current.pathOS);
      if (!isInternal) {
        trueState->pathOS << "1";
        falseState->pathOS << "0";
      }
    }
    if (symPathWriter) {
      falseState->symPathOS = symPathWriter->open(current.symPathOS);
      if (!isInternal) {
        trueState->symPathOS << "1";
        falseState->symPathOS << "0";
      }
    }

    addConstraint(*trueState, condition);
    addConstraint(*falseState, Expr::createIsZero(condition));

    // Kinda gross, do we even really still want this option?
    if (MaxDepth && MaxDepth<=trueState->depth) {
      terminateStateEarly(*trueState, "max-depth exceeded.");
      terminateStateEarly(*falseState, "max-depth exceeded.");
      return StatePair(0, 0);
    }

    return StatePair(trueState, falseState);
  }
}

void Executor::addConstraint(ExecutionState &state, ref<Expr> condition) {
  if (ConstantExpr *CE = dyn_cast<ConstantExpr>(condition)) {
    if (!CE->isTrue())
      llvm::report_fatal_error("attempt to add invalid constraint");
    return;
  }

  // Check to see if this constraint violates seeds.
  std::map< ExecutionState*, std::vector<SeedInfo> >::iterator it = 
    seedMap.find(&state);
  if (it != seedMap.end()) {
    bool warn = false;
    for (std::vector<SeedInfo>::iterator siit = it->second.begin(), 
           siie = it->second.end(); siit != siie; ++siit) {
      bool res;
      bool success = 
        solver->mustBeFalse(state, siit->assignment.evaluate(condition), res);
      assert(success && "FIXME: Unhandled solver failure");
      (void) success;
      if (res) {
        siit->patchSeed(state, condition, solver);
        warn = true;
      }
    }
    if (warn)
      klee_warning("seeds patched for violating constraint"); 
  }

  state.addConstraint(condition);
  if (ivcEnabled)
    doImpliedValueConcretization(state, condition, 
                                 ConstantExpr::alloc(1, Expr::Bool));
}

ref<klee::ConstantExpr> Executor::evalConstant(const Constant *c) {
  if (const llvm::ConstantExpr *ce = dyn_cast<llvm::ConstantExpr>(c)) {
    return evalConstantExpr(ce);
  } else {
    if (const ConstantInt *ci = dyn_cast<ConstantInt>(c)) {
      return ConstantExpr::alloc(ci->getValue());
    } else if (const ConstantFP *cf = dyn_cast<ConstantFP>(c)) {      
      return ConstantExpr::alloc(cf->getValueAPF().bitcastToAPInt());
    } else if (const GlobalValue *gv = dyn_cast<GlobalValue>(c)) {
      return globalAddresses.find(gv)->second;
    } else if (isa<ConstantPointerNull>(c)) {
      return Expr::createPointer(0);
    } else if (isa<UndefValue>(c) || isa<ConstantAggregateZero>(c)) {
      return ConstantExpr::create(0, getWidthForLLVMType(c->getType()));
#if LLVM_VERSION_CODE >= LLVM_VERSION(3, 1)
    } else if (const ConstantDataSequential *cds =
                 dyn_cast<ConstantDataSequential>(c)) {
      std::vector<ref<Expr> > kids;
      for (unsigned i = 0, e = cds->getNumElements(); i != e; ++i) {
        ref<Expr> kid = evalConstant(cds->getElementAsConstant(i));
        kids.push_back(kid);
      }
      ref<Expr> res = ConcatExpr::createN(kids.size(), kids.data());
      return cast<ConstantExpr>(res);
#endif
    } else if (const ConstantStruct *cs = dyn_cast<ConstantStruct>(c)) {
      const StructLayout *sl = kmodule->targetData->getStructLayout(cs->getType());
      llvm::SmallVector<ref<Expr>, 4> kids;
      for (unsigned i = cs->getNumOperands(); i != 0; --i) {
        unsigned op = i-1;
        ref<Expr> kid = evalConstant(cs->getOperand(op));

        uint64_t thisOffset = sl->getElementOffsetInBits(op),
                 nextOffset = (op == cs->getNumOperands() - 1)
                              ? sl->getSizeInBits()
                              : sl->getElementOffsetInBits(op+1);
        if (nextOffset-thisOffset > kid->getWidth()) {
          uint64_t paddingWidth = nextOffset-thisOffset-kid->getWidth();
          kids.push_back(ConstantExpr::create(0, paddingWidth));
        }

        kids.push_back(kid);
      }
      ref<Expr> res = ConcatExpr::createN(kids.size(), kids.data());
      return cast<ConstantExpr>(res);
    } else if (const ConstantArray *ca = dyn_cast<ConstantArray>(c)){
      llvm::SmallVector<ref<Expr>, 4> kids;
      for (unsigned i = ca->getNumOperands(); i != 0; --i) {
        unsigned op = i-1;
        ref<Expr> kid = evalConstant(ca->getOperand(op));
        kids.push_back(kid);
      }
      ref<Expr> res = ConcatExpr::createN(kids.size(), kids.data());
      return cast<ConstantExpr>(res);
    } else {
      // Constant{Vector}
      llvm::report_fatal_error("invalid argument to evalConstant()");
    }
  }
}

const Cell& Executor::eval(KInstruction *ki, unsigned index, 
                           ExecutionState &state) const {
  assert(index < ki->inst->getNumOperands());
  int vnumber = ki->operands[index];

  assert(vnumber != -1 &&
         "Invalid operand to eval(), not a value or constant!");

  // Determine if this is a constant or not.
  if (vnumber < 0) {
    unsigned index = -vnumber - 2;
    return kmodule->constantTable[index];
  } else {
    unsigned index = vnumber;
    StackFrame &sf = state.stack.back();
    return sf.locals[index];
  }
}

void Executor::bindLocal(KInstruction *target, ExecutionState &state, 
                         ref<Expr> value) {
  if(!target)
    return;
  getDestCell(state, target).value = value;
}

void Executor::bindArgument(KFunction *kf, unsigned index, 
                            ExecutionState &state, ref<Expr> value) {
  getArgumentCell(state, kf, index).value = value;
}

ref<Expr> Executor::toUnique(const ExecutionState &state, 
                             ref<Expr> &e) {
  ref<Expr> result = e;

  if (!isa<ConstantExpr>(e)) {
    ref<ConstantExpr> value;
    bool isTrue = false;

    solver->setTimeout(coreSolverTimeout);      
    if (solver->getValue(state, e, value) &&
        solver->mustBeTrue(state, EqExpr::create(e, value), isTrue) &&
        isTrue)
      result = value;
    solver->setTimeout(0);
  }
  
  return result;
}


/* Concretize the given expression, and return a possible constant value. 
   'reason' is just a documentation string stating the reason for concretization. */
ref<klee::ConstantExpr> 
Executor::toConstant(ExecutionState &state, 
                     ref<Expr> e,
                     const char *reason) {
  e = state.constraints.simplifyExpr(e);
  if (ConstantExpr *CE = dyn_cast<ConstantExpr>(e))
    return CE;

  ref<ConstantExpr> value;
  bool success = solver->getValue(state, e, value);
  assert(success && "FIXME: Unhandled solver failure");
  (void) success;

  std::string str;
  llvm::raw_string_ostream os(str);
  os << "silently concretizing (reason: " << reason << ") expression " << e
     << " to value " << value << " (" << (*(state.pc)).info->file << ":"
     << (*(state.pc)).info->line << ")";

  if (AllExternalWarnings)
    klee_warning(reason, os.str().c_str());
  else
    klee_warning_once(reason, "%s", os.str().c_str());

  addConstraint(state, EqExpr::create(e, value));
    
  return value;
}

void Executor::executeGetValue(ExecutionState &state,
                               ref<Expr> e,
                               KInstruction *target) {
  e = state.constraints.simplifyExpr(e);
  std::map< ExecutionState*, std::vector<SeedInfo> >::iterator it = 
    seedMap.find(&state);
  if (it==seedMap.end() || isa<ConstantExpr>(e)) {
    ref<ConstantExpr> value;
    bool success = solver->getValue(state, e, value);
    assert(success && "FIXME: Unhandled solver failure");
    (void) success;
    bindLocal(target, state, value);
  } else {
    std::set< ref<Expr> > values;
    for (std::vector<SeedInfo>::iterator siit = it->second.begin(), 
           siie = it->second.end(); siit != siie; ++siit) {
      ref<ConstantExpr> value;
      bool success = 
        solver->getValue(state, siit->assignment.evaluate(e), value);
      assert(success && "FIXME: Unhandled solver failure");
      (void) success;
      values.insert(value);
    }
    
    std::vector< ref<Expr> > conditions;
    for (std::set< ref<Expr> >::iterator vit = values.begin(), 
           vie = values.end(); vit != vie; ++vit)
      conditions.push_back(EqExpr::create(e, *vit));

    std::vector<ExecutionState*> branches;
    
    branch(state, conditions, branches);
    
    std::vector<ExecutionState*>::iterator bit = branches.begin();
    for (std::set< ref<Expr> >::iterator vit = values.begin(), 
           vie = values.end(); vit != vie; ++vit) {
      ExecutionState *es = *bit;
      if (es)
        bindLocal(target, *es, *vit);
      ++bit;
    }
  }
}

void Executor::printDebugInstructions(ExecutionState &state) {
  // check do not print
  if (DebugPrintInstructions.size() == 0)
	  return;

  llvm::raw_ostream *stream = 0;
  if (optionIsSet(DebugPrintInstructions, STDERR_ALL) ||
      optionIsSet(DebugPrintInstructions, STDERR_SRC) ||
      optionIsSet(DebugPrintInstructions, STDERR_COMPACT))
    stream = &llvm::errs();
  else
    stream = &debugLogBuffer;

  if (!optionIsSet(DebugPrintInstructions, STDERR_COMPACT) &&
      !optionIsSet(DebugPrintInstructions, FILE_COMPACT)) {
    (*stream) << "     ";
    state.pc->printFileLine(*stream);
    (*stream) << ":";
  }

  (*stream) << state.pc->info->id;

  if (optionIsSet(DebugPrintInstructions, STDERR_ALL) ||
      optionIsSet(DebugPrintInstructions, FILE_ALL))
    (*stream) << ":" << *(state.pc->inst);
  (*stream) << "\n";

  if (optionIsSet(DebugPrintInstructions, FILE_ALL) ||
      optionIsSet(DebugPrintInstructions, FILE_COMPACT) ||
      optionIsSet(DebugPrintInstructions, FILE_SRC)) {
    debugLogBuffer.flush();
    (*debugInstFile) << debugLogBuffer.str();
    debugBufferString = "";
  }
}

void Executor::stepInstruction(ExecutionState &state) {
  printDebugInstructions(state);
  if (statsTracker)
    statsTracker->stepInstruction(state);

  ++stats::instructions;
  state.prevPC = state.pc;
  ++state.pc;

  if (stats::instructions==StopAfterNInstructions)
    haltExecution = true;
}

void Executor::executeCall(ExecutionState &state, 
                           KInstruction *ki,
                           Function *f,
                           std::vector< ref<Expr> > &arguments) {
  Instruction *i = ki->inst;
  if (f && f->isDeclaration()) {
    switch(f->getIntrinsicID()) {
    case Intrinsic::not_intrinsic:
      // state may be destroyed by this call, cannot touch
      callExternalFunction(state, ki, f, arguments);
      break;
        
      // va_arg is handled by caller and intrinsic lowering, see comment for
      // ExecutionState::varargs
    case Intrinsic::vastart:  {
      StackFrame &sf = state.stack.back();

      // varargs can be zero if no varargs were provided
      if (!sf.varargs)
        return;

      // FIXME: This is really specific to the architecture, not the pointer
      // size. This happens to work for x86-32 and x86-64, however.
      Expr::Width WordSize = Context::get().getPointerWidth();
      if (WordSize == Expr::Int32) {
        executeMemoryOperation(state, true, arguments[0], 
                               sf.varargs->getBaseExpr(), 0);
      } else {
        assert(WordSize == Expr::Int64 && "Unknown word size!");

        // x86-64 has quite complicated calling convention. However,
        // instead of implementing it, we can do a simple hack: just
        // make a function believe that all varargs are on stack.
        executeMemoryOperation(state, true, arguments[0],
                               ConstantExpr::create(48, 32), 0); // gp_offset
        executeMemoryOperation(state, true,
                               AddExpr::create(arguments[0], 
                                               ConstantExpr::create(4, 64)),
                               ConstantExpr::create(304, 32), 0); // fp_offset
        executeMemoryOperation(state, true,
                               AddExpr::create(arguments[0], 
                                               ConstantExpr::create(8, 64)),
                               sf.varargs->getBaseExpr(), 0); // overflow_arg_area
        executeMemoryOperation(state, true,
                               AddExpr::create(arguments[0], 
                                               ConstantExpr::create(16, 64)),
                               ConstantExpr::create(0, 64), 0); // reg_save_area
      }
      break;
    }
    case Intrinsic::vaend:
      // va_end is a noop for the interpreter.
      //
      // FIXME: We should validate that the target didn't do something bad
      // with va_end, however (like call it twice).
      break;
        
    case Intrinsic::vacopy:
      // va_copy should have been lowered.
      //
      // FIXME: It would be nice to check for errors in the usage of this as
       // well.
    default:
      klee_error("unknown intrinsic: %s", f->getName().data());
    }

    if (InvokeInst *ii = dyn_cast<InvokeInst>(i))
      transferToBasicBlock(ii->getNormalDest(), i->getParent(), state);
  } else {


    // HKLEE: Just debug
    if (f && (symStubs.find(f->getName()) != symStubs.end()))
      {
	int idx = symStubs[f->getName()];
	int arg = (idx == 0 ? 1 : state.stack.back().argAttrs[idx]);
	(*debugHeapFile) << "1 " << f->getName() << " argAttrs[" << idx << "]  = " << arg << " framenbr = " << state.stack.size() << "\n";	
      }
    
    // FIXME: I'm not really happy about this reliance on prevPC but it is ok, I
    // guess. This just done to avoid having to pass KInstIterator everywhere
    // instead of the actual instruction, since we can't make a KInstIterator
    // from just an instruction (unlike LLVM).
    KFunction *kf = kmodule->functionMap[f];
    state.pushFrame(state.prevPC, kf);
    state.pc = kf->instructions;

    if (statsTracker)
      statsTracker->framePushed(state, &state.stack[state.stack.size()-2]);

    // XXX: HEAP KLEE debug
    if (f && (symStubs.find(f->getName()) != symStubs.end()))
      {
	(*debugHeapFile) << "2 " << f->getName() << " framenbr = " << state.stack.size() << "\n";
	//llvm::errs() << "2 STRLEN/ATOI "  << " argAttrs[0]  = " << state.stack.back().argAttrs[0] << " framenbr = " << state.stack.size() << "\n";	
      }
    
     // TODO: support "byval" parameter attribute
     // TODO: support zeroext, signext, sret attributes
    unsigned callingArgs = arguments.size();
    unsigned funcArgs = f->arg_size();
    if (!f->isVarArg()) {
      if (callingArgs > funcArgs) {
        klee_warning_once(f, "calling %s with extra arguments.", 
                          f->getName().data());
      } else if (callingArgs < funcArgs) {
        terminateStateOnError(state, "calling function with too few arguments",
                              User);
        return;
      }
    } else {
      Expr::Width WordSize = Context::get().getPointerWidth();

      if (callingArgs < funcArgs) {
        terminateStateOnError(state, "calling function with too few arguments",
                              User);
        return;
      }

      StackFrame &sf = state.stack.back();
      unsigned size = 0;
      bool requires16ByteAlignment = false;
      for (unsigned i = funcArgs; i < callingArgs; i++) {
        // FIXME: This is really specific to the architecture, not the pointer
        // size. This happens to work for x86-32 and x86-64, however.
        if (WordSize == Expr::Int32) {
          size += Expr::getMinBytesForWidth(arguments[i]->getWidth());
        } else {
          Expr::Width argWidth = arguments[i]->getWidth();
          // AMD64-ABI 3.5.7p5: Step 7. Align l->overflow_arg_area upwards to a
          // 16 byte boundary if alignment needed by type exceeds 8 byte
          // boundary.
          //
          // Alignment requirements for scalar types is the same as their size
          if (argWidth > Expr::Int64) {
             size = llvm::RoundUpToAlignment(size, 16);
             requires16ByteAlignment = true;
          }
          size += llvm::RoundUpToAlignment(argWidth, WordSize) / 8;
        }
      }

      MemoryObject *mo = sf.varargs =
          memory->allocate(size, true, false, state.prevPC->inst,
                           (requires16ByteAlignment ? 16 : 8));
      if (!mo && size) {
        terminateStateOnExecError(state, "out of memory (varargs)");
        return;
      }

      if (mo) {
        if ((WordSize == Expr::Int64) && (mo->guest_address() & 15) &&
            requires16ByteAlignment) {
          // Both 64bit Linux/Glibc and 64bit MacOSX should align to 16 bytes.
          klee_warning_once(
              0, "While allocating varargs: malloc did not align to 16 bytes.");
        }

        ObjectState *os = bindObjectInState(state, mo, true);
        unsigned offset = 0;
        for (unsigned i = funcArgs; i < callingArgs; i++) {
          // FIXME: This is really specific to the architecture, not the pointer
          // size. This happens to work for x86-32 and x86-64, however.
          if (WordSize == Expr::Int32) {
            os->write(offset, arguments[i]);
            offset += Expr::getMinBytesForWidth(arguments[i]->getWidth());
          } else {
            assert(WordSize == Expr::Int64 && "Unknown word size!");

            Expr::Width argWidth = arguments[i]->getWidth();
            if (argWidth > Expr::Int64) {
              offset = llvm::RoundUpToAlignment(offset, 16);
            }
            os->write(offset, arguments[i]);
            offset += llvm::RoundUpToAlignment(argWidth, WordSize) / 8;
          }
        }
      }
    }

    unsigned numFormals = f->arg_size();
    for (unsigned i=0; i<numFormals; ++i) 
      bindArgument(kf, i, state, arguments[i]);
  }

  // XXX: Just debug
  if (f && (symStubs.find(f->getName()) != symStubs.end()))
    {
      (*debugHeapFile) << "3 " << f->getName() << " framenbr = " << state.stack.size() << "\n";	
    }
  
}

void Executor::transferToBasicBlock(BasicBlock *dst, BasicBlock *src, 
                                    ExecutionState &state) {
  // Note that in general phi nodes can reuse phi values from the same
  // block but the incoming value is the eval() result *before* the
  // execution of any phi nodes. this is pathological and doesn't
  // really seem to occur, but just in case we run the PhiCleanerPass
  // which makes sure this cannot happen and so it is safe to just
  // eval things in order. The PhiCleanerPass also makes sure that all
  // incoming blocks have the same order for each PHINode so we only
  // have to compute the index once.
  //
  // With that done we simply set an index in the state so that PHI
  // instructions know which argument to eval, set the pc, and continue.
  
  // XXX this lookup has to go ?
  KFunction *kf = state.stack.back().kf;
  unsigned entry = kf->basicBlockEntry[dst];
  state.pc = &kf->instructions[entry];
  if (state.pc->inst->getOpcode() == Instruction::PHI) {
    PHINode *first = static_cast<PHINode*>(state.pc->inst);
    state.incomingBBIndex = first->getBasicBlockIndex(src);
  }
}

/// Compute the true target of a function call, resolving LLVM and KLEE aliases
/// and bitcasts.
Function* Executor::getTargetFunction(Value *calledVal, ExecutionState &state) {
  SmallPtrSet<const GlobalValue*, 3> Visited;

  Constant *c = dyn_cast<Constant>(calledVal);
  if (!c)
    return 0;

  while (true) {
    if (GlobalValue *gv = dyn_cast<GlobalValue>(c)) {
#if LLVM_VERSION_CODE >= LLVM_VERSION(3, 6)
      if (!Visited.insert(gv).second)
        return 0;
#else
      if (!Visited.insert(gv))
        return 0;
#endif
      std::string alias = state.getFnAlias(gv->getName());
      if (alias != "") {
        llvm::Module* currModule = kmodule->module;
        GlobalValue *old_gv = gv;
        gv = currModule->getNamedValue(alias);
        if (!gv) {
          klee_error("Function %s(), alias for %s not found!\n", alias.c_str(),
                     old_gv->getName().str().c_str());
        }
      }
     
      if (Function *f = dyn_cast<Function>(gv))
        return f;
      else if (GlobalAlias *ga = dyn_cast<GlobalAlias>(gv))
        c = ga->getAliasee();
      else
        return 0;
    } else if (llvm::ConstantExpr *ce = dyn_cast<llvm::ConstantExpr>(c)) {
      if (ce->getOpcode()==Instruction::BitCast)
        c = ce->getOperand(0);
      else
        return 0;
    } else
      return 0;
  }
}

/// TODO remove?
static bool isDebugIntrinsic(const Function *f, KModule *KM) {
  return false;
}

static inline const llvm::fltSemantics * fpWidthToSemantics(unsigned width) {
  switch(width) {
  case Expr::Int32:
    return &llvm::APFloat::IEEEsingle;
  case Expr::Int64:
    return &llvm::APFloat::IEEEdouble;
  case Expr::Fl80:
    return &llvm::APFloat::x87DoubleExtended;
  default:
    return 0;
  }
}


void Executor::executeInstruction(ExecutionState &state, KInstruction *ki) {
  Instruction *i = ki->inst;

  // Print AddressSpace symbolic state at each instruction
  // Wrap this around an option
  for (MemoryMap::iterator it = state.addressSpace.objects.begin();
       it != state.addressSpace.objects.end(); ++it)
    {
      ObjectState *os = it->second;
      os->print_symbolics();
    }

  // Print LLVM instruction before symbolic execution
  Function *f = i->getParent()->getParent();
  (*debugHeapFile) << "[PC:" << ki->info->assemblyLine << "] "
                   //<< "[PC:" << (*state.pc).info->assemblyLine << "][PREVPC:" << (*state.prevPC).info->assemblyLine << "] "
		   << "LLVM INSTR: " << i->getOpcodeName()
		   << " (depth = " << state.stack.size() << ") Parent func = " << f->getName() << "\n";
  debugHeapFile->flush();
  
  switch (i->getOpcode()) {
    // Control flow
  case Instruction::Ret: {
    ReturnInst *ri = cast<ReturnInst>(i);
    KInstIterator kcaller = state.stack.back().caller;
    Instruction *caller = kcaller ? kcaller->inst : 0;
    bool isVoidReturn = (ri->getNumOperands() == 0);
    ref<Expr> result = ConstantExpr::alloc(0, Expr::Bool);
    
    if (!isVoidReturn) {
      result = eval(ki, 0, state).value;
    }
    
    if (state.stack.size() <= 1) {
      assert(!caller && "caller set on initial stack frame");
      terminateStateOnExit(state);
    } else {
      state.popFrame();

      if (statsTracker)
        statsTracker->framePopped(state);

      if (InvokeInst *ii = dyn_cast<InvokeInst>(caller)) {
        transferToBasicBlock(ii->getNormalDest(), caller->getParent(), state);
      } else {
        state.pc = kcaller;
        ++state.pc;
      }

      if (!isVoidReturn) {


      BasicBlock *b = i->getParent();
      Function *f = b->getParent();
      std::string str = f->getName();
      bool	  ret_is_symbolic = false;
      ref<Expr> e = ConstantExpr::alloc(0, Expr::Int32);
      static unsigned id;
      const Array *array = arrayCache.CreateArray("rrws_arr" + llvm::utostr(++id), Expr::getMinBytesForWidth(e->getWidth()));
      ref<Expr> sym_result = Expr::createTempRead(array, e->getWidth());

      bool isSymbolicStub = (symStubs.find(str.c_str()) != symStubs.end());
      
      if (isSymbolicStub)
	{
	  int argIndex = symStubs[str.c_str()];
	  
	  StackFrame &sf = state.stack.back();
	  std::vector<bool> argAttrs = sf.argAttrs;
	  
	  //StackFrame &sf2 = state.stack.back()
	  //std::vector<bool> argAttrs2 = sf2.argAttrs;

	  KFunction *kf = sf.kf;
	  std::string funcname = (kf == NULL || kf->function == NULL ? std::string("UNK") : std::string(kf->function->getName()));
	  (*debugHeapFile) << "StackFrame Function = " << funcname << " framenbr = " << state.stack.size() << "\n";

	  if (SymStubs)
	    {
	      if (argIndex == 0 || argAttrs[argIndex] == 1)
		ret_is_symbolic = true;
	      else
		ret_is_symbolic = false;
	    }
	  else
	    ret_is_symbolic = false;
	  
	  (*debugHeapFile) << "RETURN of " << str.c_str() << " is symbolic: " << ret_is_symbolic
		           << " argAttrs[Idx]  = " << argAttrs[argIndex]
		           << " SymStubOpt: " << SymStubs << "\n";
	}
      
	
        LLVM_TYPE_Q Type *t = caller->getType();
        if (t != Type::getVoidTy(i->getContext())) {
          // may need to do coercion due to bitcasts
          Expr::Width from = result->getWidth();
          Expr::Width to = getWidthForLLVMType(t);
            
          if (from != to) {
            CallSite cs = (isa<InvokeInst>(caller) ? CallSite(cast<InvokeInst>(caller)) : 
                           CallSite(cast<CallInst>(caller)));

            // XXX need to check other param attrs ?
#if LLVM_VERSION_CODE >= LLVM_VERSION(3, 3)
      bool isSExt = cs.paramHasAttr(0, llvm::Attribute::SExt);
#elif LLVM_VERSION_CODE >= LLVM_VERSION(3, 2)
	    bool isSExt = cs.paramHasAttr(0, llvm::Attributes::SExt);
#else
	    bool isSExt = cs.paramHasAttr(0, llvm::Attribute::SExt);
#endif
            if (isSExt) {
	      if (ret_is_symbolic == false)
		result = SExtExpr::create(result, to);
	      else
		sym_result = SExtExpr::create(sym_result, to);
					      
            } else {
	      if (ret_is_symbolic == false)
		result = ZExtExpr::create(result, to);
	      else
		sym_result = ZExtExpr::create(sym_result, to);
            }
	    
          }

	  if (ret_is_symbolic)
	    {
	      (*debugHeapFile) << "SET return value AS symbolic \n";
	      bindLocal(kcaller, state, sym_result);
	      //ref<Expr> eq = NotOptimizedExpr::create(EqExpr::create(e, sym_result));     
	      //state.addConstraint(eq);

	      ConstantExpr* test = dyn_cast<ConstantExpr>(sym_result);
	      if (test)
		{
		  (*debugHeapFile) << "RET value could be cast to ConstantExpr \n";
		}
	      else
		{
		  (*debugHeapFile) << "RET value could not be cast to ConstantExpr \n";
		}
	      fflush(stdout);
	    }
	  else
	    bindLocal(kcaller, state, result);

	  
        }
      } else {
        // We check that the return value has no users instead of
        // checking the type, since C defaults to returning int for
        // undeclared functions.
        if (!caller->use_empty()) {
          terminateStateOnExecError(state, "return void when caller expected a result");
        }
      }
    }      
    break;
  }
#if LLVM_VERSION_CODE < LLVM_VERSION(3, 1)
  case Instruction::Unwind: {
    for (;;) {
      KInstruction *kcaller = state.stack.back().caller;
      state.popFrame();

      if (statsTracker)
        statsTracker->framePopped(state);

      if (state.stack.empty()) {
        terminateStateOnExecError(state, "unwind from initial stack frame");
        break;
      } else {
        Instruction *caller = kcaller->inst;
        if (InvokeInst *ii = dyn_cast<InvokeInst>(caller)) {
          transferToBasicBlock(ii->getUnwindDest(), caller->getParent(), state);
          break;
        }
      }
    }
    break;
  }
#endif
  case Instruction::Br: {
    BranchInst *bi = cast<BranchInst>(i);
    if (bi->isUnconditional()) {
      transferToBasicBlock(bi->getSuccessor(0), bi->getParent(), state);
    } else {
      // FIXME: Find a way that we don't have this hidden dependency.
      assert(bi->getCondition() == bi->getOperand(0) &&
             "Wrong operand index!");
      ref<Expr> cond = eval(ki, 0, state).value;
      Executor::StatePair branches = fork(state, cond, false);

      // JV: Add edges for states
      this->trackEdges(state, branches, Executor::EDGE_SYM, "br2");
      
      // NOTE: There is a hidden dependency here, markBranchVisited
      // requires that we still be in the context of the branch
      // instruction (it reuses its statistic id). Should be cleaned
      // up with convenient instruction specific data.
      if (statsTracker && state.stack.back().kf->trackCoverage)
        statsTracker->markBranchVisited(branches.first, branches.second);

      if (branches.first)
        transferToBasicBlock(bi->getSuccessor(0), bi->getParent(), *branches.first);
      if (branches.second)
        transferToBasicBlock(bi->getSuccessor(1), bi->getParent(), *branches.second);
    }
    break;
  }
  case Instruction::Switch: {
    SwitchInst *si = cast<SwitchInst>(i);
    ref<Expr> cond = eval(ki, 0, state).value;
    BasicBlock *bb = si->getParent();

    cond = toUnique(state, cond);
    if (ConstantExpr *CE = dyn_cast<ConstantExpr>(cond)) {
      // Somewhat gross to create these all the time, but fine till we
      // switch to an internal rep.
      LLVM_TYPE_Q llvm::IntegerType *Ty = 
        cast<IntegerType>(si->getCondition()->getType());
      ConstantInt *ci = ConstantInt::get(Ty, CE->getZExtValue());
#if LLVM_VERSION_CODE >= LLVM_VERSION(3, 1)
      unsigned index = si->findCaseValue(ci).getSuccessorIndex();
#else
      unsigned index = si->findCaseValue(ci);
#endif
      transferToBasicBlock(si->getSuccessor(index), si->getParent(), state);
    } else {
      // Handle possible different branch targets

      // We have the following assumptions:
      // - each case value is mutual exclusive to all other values including the
      //   default value
      // - order of case branches is based on the order of the expressions of
      //   the scase values, still default is handled last
      std::vector<BasicBlock *> bbOrder;
      std::map<BasicBlock *, ref<Expr> > branchTargets;

      std::map<ref<Expr>, BasicBlock *> expressionOrder;

      // Iterate through all non-default cases and order them by expressions
#if LLVM_VERSION_CODE >= LLVM_VERSION(3, 1)
      for (SwitchInst::CaseIt i = si->case_begin(), e = si->case_end(); i != e;
           ++i) {
        ref<Expr> value = evalConstant(i.getCaseValue());
#else
      for (unsigned i = 1, cases = si->getNumCases(); i < cases; ++i) {
        ref<Expr> value = evalConstant(si->getCaseValue(i));
#endif

#if LLVM_VERSION_CODE >= LLVM_VERSION(3, 1)
        BasicBlock *caseSuccessor = i.getCaseSuccessor();
#else
        BasicBlock *caseSuccessor = si->getSuccessor(i);
#endif
        expressionOrder.insert(std::make_pair(value, caseSuccessor));
      }

      // Track default branch values
      ref<Expr> defaultValue = ConstantExpr::alloc(1, Expr::Bool);

      // iterate through all non-default cases but in order of the expressions
      for (std::map<ref<Expr>, BasicBlock *>::iterator
               it = expressionOrder.begin(),
               itE = expressionOrder.end();
           it != itE; ++it) {
        ref<Expr> match = EqExpr::create(cond, it->first);

        // Make sure that the default value does not contain this target's value
        defaultValue = AndExpr::create(defaultValue, Expr::createIsZero(match));

        // Check if control flow could take this case
        bool result;
        bool success = solver->mayBeTrue(state, match, result);
        assert(success && "FIXME: Unhandled solver failure");
        (void) success;
        if (result) {
          BasicBlock *caseSuccessor = it->second;

          // Handle the case that a basic block might be the target of multiple
          // switch cases.
          // Currently we generate an expression containing all switch-case
          // values for the same target basic block. We spare us forking too
          // many times but we generate more complex condition expressions
          // TODO Add option to allow to choose between those behaviors
          std::pair<std::map<BasicBlock *, ref<Expr> >::iterator, bool> res =
              branchTargets.insert(std::make_pair(
                  caseSuccessor, ConstantExpr::alloc(0, Expr::Bool)));

          res.first->second = OrExpr::create(match, res.first->second);

          // Only add basic blocks which have not been target of a branch yet
          if (res.second) {
            bbOrder.push_back(caseSuccessor);
          }
        }
      }

      // Check if control could take the default case
      bool res;
      bool success = solver->mayBeTrue(state, defaultValue, res);
      assert(success && "FIXME: Unhandled solver failure");
      (void) success;
      if (res) {
        std::pair<std::map<BasicBlock *, ref<Expr> >::iterator, bool> ret =
            branchTargets.insert(
                std::make_pair(si->getDefaultDest(), defaultValue));
        if (ret.second) {
          bbOrder.push_back(si->getDefaultDest());
        }
      }

      // Fork the current state with each state having one of the possible
      // successors of this switch
      std::vector< ref<Expr> > conditions;
      for (std::vector<BasicBlock *>::iterator it = bbOrder.begin(),
                                               ie = bbOrder.end();
           it != ie; ++it) {
        conditions.push_back(branchTargets[*it]);
      }
      std::vector<ExecutionState*> branches;
      branch(state, conditions, branches);

      std::vector<ExecutionState*>::iterator bit = branches.begin();
      for (std::vector<BasicBlock *>::iterator it = bbOrder.begin(),
                                               ie = bbOrder.end();
           it != ie; ++it) {
        ExecutionState *es = *bit;
        if (es)
          transferToBasicBlock(*it, bb, *es);
        ++bit;
      }
    }
    break;
 }
  case Instruction::Unreachable:
    // Note that this is not necessarily an internal bug, llvm will
    // generate unreachable instructions in cases where it knows the
    // program will crash. So it is effectively a SEGV or internal
    // error.
    terminateStateOnExecError(state, "reached \"unreachable\" instruction");
    break;

  case Instruction::Invoke:
  case Instruction::Call: {
    CallSite cs(i);

    unsigned numArgs = cs.arg_size();
    Value *fp = cs.getCalledValue();
    Function *f = getTargetFunction(fp, state);

    /**************/
    /* Track control flow edge to graph at termination time */
    Function *fparent = i->getParent()->getParent();
    std::string fct_src_name = (fparent == NULL ? "unknown_fsrc" : fparent->getName());
    std::string fct_dst_name = (f == NULL ? "unknown_fdst" : f->getName());

    // Only print the part of the state space that is outside klee 
    if (fct_dst_name.find("klee") == std::string::npos &&
	fct_src_name.find("klee") == std::string::npos)
      {	
	std::replace(fct_src_name.begin(), fct_src_name.end(), '.', '_');
	std::replace(fct_dst_name.begin(), fct_dst_name.end(), '.', '_');
	if (ControlStates.find(fct_src_name) == ControlStates.end())
	  ControlStates[fct_src_name] = std::make_pair(false,fct_src_name);
	if (ControlStates.find(fct_dst_name) == ControlStates.end())
	  ControlStates[fct_dst_name] = std::make_pair(false,fct_dst_name);
	
	StringPair fpair = std::make_pair(fct_src_name,fct_dst_name);
	if (ControlEdges.count(fpair) == 0)
	  ControlEdges[fpair] = "";
      }
    /*************/
    
    // Skip debug intrinsics, we can't evaluate their metadata arguments.
    if (f && isDebugIntrinsic(f, kmodule))
      break;
    
    if (isa<InlineAsm>(fp)) {
      terminateStateOnExecError(state, "inline assembly is unsupported");
      break;
    }
    // evaluate arguments
    std::vector< ref<Expr> > arguments;
    arguments.reserve(numArgs);

    for (unsigned j=0; j<numArgs; ++j)
      arguments.push_back(eval(ki, j+1, state).value);

    std::vector<bool> argAttrs;
    
    if (f && (symStubs.find(f->getName()) != symStubs.end()))
    {
      std::string funcName = f->getName();
      (*debugHeapFile) << "Executor::executeInstruction()::Call: calling " << funcName << "\n";
      unsigned numFormals = f->arg_size();

      // This iterator gives us _static_ information about function arguments, e.g. its type
      llvm::Function::arg_iterator arg_it = f->arg_begin(); 
      for (unsigned i=0; i<numFormals; ++i) 
      {
        llvm::Value *arg = arg_it;
        llvm::Type *arg_type = arg->getType();
        if (isa<llvm::PointerType>(arg_type))
	{
          (*debugHeapFile) << "Executor::executeInstruction()::Call: argument[" << i << "] is a pointer\n";
          ConstantExpr *address = dyn_cast<ConstantExpr>(arguments[i]);
	  if (!address)
	    {
	      (*debugHeapFile) << "Executor::executeInstruction()::Call: argument is a symbolic pointer!\n";
	    }
	  else
	  {
            (*debugHeapFile) << "Executor::executeInstruction()::Call: argument is a constant pointer, resolving the corresponding memory object!\n";
            ObjectPair op;
            bool success;
            solver->setTimeout(coreSolverTimeout);
            success = state.addressSpace.resolveOne(cast<ConstantExpr>(address), op);
            solver->setTimeout(0);
	    assert(success && "[-] Failed to resolve memobject for Symbolic Stub argument");
            //const MemoryObject *mo = op.first; //note: MemoryObject stores meta information about object (e.g. its size, and address)
            const ObjectState *os = op.second;   //note: ObjectStates stores the content of the object (either symbolic or concrete)
            ref<Expr> first_byte = os->read(0, 8); // at offset 0, read an 8-bit element.
            ConstantExpr *first_byte_is_const = dyn_cast<ConstantExpr>(first_byte);

	    if (first_byte_is_const)
	      {
		(*debugHeapFile) << "Executor::executeInstruction()::Call: The first byte of " << funcName << " param is constant!\n";
		argAttrs.push_back(false);
	      }
	    else
	      {
		(*debugHeapFile) << "Executor::executeInstruction()::Call: The first byte of " << funcName << " param is symbolic!\n";
		argAttrs.push_back(true);
	      }
	  }
        } 
	++arg_it;
      }
    }

    StackFrame &sf = state.stack.back();
    sf.argAttrs = argAttrs;

    // XXX: Just debug
    if (f && (symStubs.find(f->getName()) != symStubs.end()))
      {
	int idx = symStubs[f->getName()];
	int arg = (idx == 0 ? 1 : state.stack.back().argAttrs[idx]);
	
	(*debugHeapFile) << f->getName() << " argAttrs[" << idx << "]  = " << arg << " framenbr = " << state.stack.size() << "\n";	
	KFunction *kf = sf.kf;
	std::string funcname = (kf == NULL || kf->function == NULL ? std::string("UNK") : std::string(kf->function->getName()));
	(*debugHeapFile) << "ExecuteCall: StackFrame Function in which argAttrs are inserted = " << funcname << "\n";
      }
    
    if (f) {
      const FunctionType *fType = 
        dyn_cast<FunctionType>(cast<PointerType>(f->getType())->getElementType());
      const FunctionType *fpType =
        dyn_cast<FunctionType>(cast<PointerType>(fp->getType())->getElementType());

      // special case the call with a bitcast case
      if (fType != fpType) {
        assert(fType && fpType && "unable to get function type");

        // XXX check result coercion

        // XXX this really needs thought and validation
        unsigned i=0;
        for (std::vector< ref<Expr> >::iterator
               ai = arguments.begin(), ie = arguments.end();
             ai != ie; ++ai) {
          Expr::Width to, from = (*ai)->getWidth();
            
          if (i<fType->getNumParams()) {
            to = getWidthForLLVMType(fType->getParamType(i));

            if (from != to) {
              // XXX need to check other param attrs ?
#if LLVM_VERSION_CODE >= LLVM_VERSION(3, 3)
              bool isSExt = cs.paramHasAttr(i+1, llvm::Attribute::SExt);
#elif LLVM_VERSION_CODE >= LLVM_VERSION(3, 2)
	      bool isSExt = cs.paramHasAttr(i+1, llvm::Attributes::SExt);
#else
	      bool isSExt = cs.paramHasAttr(i+1, llvm::Attribute::SExt);
#endif
              if (isSExt) {
                arguments[i] = SExtExpr::create(arguments[i], to);
              } else {
                arguments[i] = ZExtExpr::create(arguments[i], to);
              }
            }
          }
            
          i++;
        }
      }
      
      if (f && (symStubs.find(f->getName()) != symStubs.end()))
	{
	  (*debugHeapFile) << "Now Going to executeCall for symbolic stub " << f->getName() << "\n";
	}
      
      executeCall(state, ki, f, arguments);

      if (f && (symStubs.find(f->getName()) != symStubs.end()))
      {
	(*debugHeapFile) << "4 " << f->getName() << " framenbr = " << state.stack.size() << "\n";	
	KFunction *kf = sf.kf;
	std::string funcname = (kf == NULL || kf->function == NULL ? std::string("UNK") : std::string(kf->function->getName()));
	(*debugHeapFile) << "ExecuteCall: StackFrame Function in which argAttrs are inserted = " << funcname << "\n";
      }
      
      
    } else {
      ref<Expr> v = eval(ki, 0, state).value;

      ExecutionState *free = &state;
      bool hasInvalid = false, first = true;

      /* XXX This is wasteful, no need to do a full evaluate since we
         have already got a value. But in the end the caches should
         handle it for us, albeit with some overhead. */
      do {
        ref<ConstantExpr> value;
        bool success = solver->getValue(*free, v, value);
        assert(success && "FIXME: Unhandled solver failure");
        (void) success;
        StatePair res = fork(*free, EqExpr::create(v, value), true);

	// JV: Add edges for states
	this->trackEdges(*free, res, Executor::EDGE_HEAP, "ctarget");
	
        if (res.first) {
          uint64_t addr = value->getZExtValue();
          if (legalFunctions.count(addr)) {
            f = (Function*) addr;

            // Don't give warning on unique resolution
            if (res.second || !first)
              klee_warning_once((void*) (unsigned long) addr, 
                                "resolved symbolic function pointer to: %s",
                                f->getName().data());

            executeCall(*res.first, ki, f, arguments);
          } else {
            if (!hasInvalid) {
              terminateStateOnExecError(state, "invalid function pointer");
              hasInvalid = true;
            }
          }
        }

        first = false;
        free = res.second;
      } while (free);
    }
    break;
  }
  case Instruction::PHI: {
#if LLVM_VERSION_CODE >= LLVM_VERSION(3, 0)
    ref<Expr> result = eval(ki, state.incomingBBIndex, state).value;
#else
    ref<Expr> result = eval(ki, state.incomingBBIndex * 2, state).value;
#endif
    bindLocal(ki, state, result);
    break;
  }

    // Special instructions
  case Instruction::Select: {
    ref<Expr> cond = eval(ki, 0, state).value;
    ref<Expr> tExpr = eval(ki, 1, state).value;
    ref<Expr> fExpr = eval(ki, 2, state).value;
    ref<Expr> result = SelectExpr::create(cond, tExpr, fExpr);
    bindLocal(ki, state, result);
    break;
  }

  case Instruction::VAArg:
    terminateStateOnExecError(state, "unexpected VAArg instruction");
    break;

    // Arithmetic / logical

  case Instruction::Add: {
    ref<Expr> left = eval(ki, 0, state).value;
    ref<Expr> right = eval(ki, 1, state).value;
    bindLocal(ki, state, AddExpr::create(left, right));
    break;
  }

  case Instruction::Sub: {
    ref<Expr> left = eval(ki, 0, state).value;
    ref<Expr> right = eval(ki, 1, state).value;
    bindLocal(ki, state, SubExpr::create(left, right));
    break;
  }
 
  case Instruction::Mul: {
    ref<Expr> left = eval(ki, 0, state).value;
    ref<Expr> right = eval(ki, 1, state).value;
    bindLocal(ki, state, MulExpr::create(left, right));
    break;
  }

  case Instruction::UDiv: {
    ref<Expr> left = eval(ki, 0, state).value;
    ref<Expr> right = eval(ki, 1, state).value;
    ref<Expr> result = UDivExpr::create(left, right);
    bindLocal(ki, state, result);
    break;
  }

  case Instruction::SDiv: {
    ref<Expr> left = eval(ki, 0, state).value;
    ref<Expr> right = eval(ki, 1, state).value;
    ref<Expr> result = SDivExpr::create(left, right);
    bindLocal(ki, state, result);
    break;
  }

  case Instruction::URem: {
    ref<Expr> left = eval(ki, 0, state).value;
    ref<Expr> right = eval(ki, 1, state).value;
    ref<Expr> result = URemExpr::create(left, right);
    bindLocal(ki, state, result);
    break;
  }
 
  case Instruction::SRem: {
    ref<Expr> left = eval(ki, 0, state).value;
    ref<Expr> right = eval(ki, 1, state).value;
    ref<Expr> result = SRemExpr::create(left, right);
    bindLocal(ki, state, result);
    break;
  }

  case Instruction::And: {
    ref<Expr> left = eval(ki, 0, state).value;
    ref<Expr> right = eval(ki, 1, state).value;
    ref<Expr> result = AndExpr::create(left, right);
    bindLocal(ki, state, result);
    break;
  }

  case Instruction::Or: {
    ref<Expr> left = eval(ki, 0, state).value;
    ref<Expr> right = eval(ki, 1, state).value;
    ref<Expr> result = OrExpr::create(left, right);
    bindLocal(ki, state, result);
    break;
  }

  case Instruction::Xor: {
    ref<Expr> left = eval(ki, 0, state).value;
    ref<Expr> right = eval(ki, 1, state).value;
    ref<Expr> result = XorExpr::create(left, right);
    bindLocal(ki, state, result);
    break;
  }

  case Instruction::Shl: {
    ref<Expr> left = eval(ki, 0, state).value;
    ref<Expr> right = eval(ki, 1, state).value;
    ref<Expr> result = ShlExpr::create(left, right);
    bindLocal(ki, state, result);
    break;
  }

  case Instruction::LShr: {
    ref<Expr> left = eval(ki, 0, state).value;
    ref<Expr> right = eval(ki, 1, state).value;
    ref<Expr> result = LShrExpr::create(left, right);
    bindLocal(ki, state, result);
    break;
  }

  case Instruction::AShr: {
    ref<Expr> left = eval(ki, 0, state).value;
    ref<Expr> right = eval(ki, 1, state).value;
    ref<Expr> result = AShrExpr::create(left, right);
    bindLocal(ki, state, result);
    break;
  }

    // Compare

  case Instruction::ICmp: {
    CmpInst *ci = cast<CmpInst>(i);
    ICmpInst *ii = cast<ICmpInst>(ci);
 
    switch(ii->getPredicate()) {
    case ICmpInst::ICMP_EQ: {
      ref<Expr> left = eval(ki, 0, state).value;
      ref<Expr> right = eval(ki, 1, state).value;
      ref<Expr> result = EqExpr::create(left, right);
      bindLocal(ki, state, result);
      break;
    }

    case ICmpInst::ICMP_NE: {
      ref<Expr> left = eval(ki, 0, state).value;
      ref<Expr> right = eval(ki, 1, state).value;
      ref<Expr> result = NeExpr::create(left, right);
      bindLocal(ki, state, result);
      break;
    }

    case ICmpInst::ICMP_UGT: {
      ref<Expr> left = eval(ki, 0, state).value;
      ref<Expr> right = eval(ki, 1, state).value;
      ref<Expr> result = UgtExpr::create(left, right);
      bindLocal(ki, state,result);
      break;
    }

    case ICmpInst::ICMP_UGE: {
      ref<Expr> left = eval(ki, 0, state).value;
      ref<Expr> right = eval(ki, 1, state).value;
      ref<Expr> result = UgeExpr::create(left, right);
      bindLocal(ki, state, result);
      break;
    }

    case ICmpInst::ICMP_ULT: {
      ref<Expr> left = eval(ki, 0, state).value;
      ref<Expr> right = eval(ki, 1, state).value;
      ref<Expr> result = UltExpr::create(left, right);
      bindLocal(ki, state, result);
      break;
    }

    case ICmpInst::ICMP_ULE: {
      ref<Expr> left = eval(ki, 0, state).value;
      ref<Expr> right = eval(ki, 1, state).value;
      ref<Expr> result = UleExpr::create(left, right);
      bindLocal(ki, state, result);
      break;
    }

    case ICmpInst::ICMP_SGT: {
      ref<Expr> left = eval(ki, 0, state).value;
      ref<Expr> right = eval(ki, 1, state).value;
      ref<Expr> result = SgtExpr::create(left, right);
      bindLocal(ki, state, result);
      break;
    }

    case ICmpInst::ICMP_SGE: {
      ref<Expr> left = eval(ki, 0, state).value;
      ref<Expr> right = eval(ki, 1, state).value;
      ref<Expr> result = SgeExpr::create(left, right);
      bindLocal(ki, state, result);
      break;
    }

    case ICmpInst::ICMP_SLT: {
      ref<Expr> left = eval(ki, 0, state).value;
      ref<Expr> right = eval(ki, 1, state).value;
      ref<Expr> result = SltExpr::create(left, right);
      bindLocal(ki, state, result);
      break;
    }

    case ICmpInst::ICMP_SLE: {
      ref<Expr> left = eval(ki, 0, state).value;
      ref<Expr> right = eval(ki, 1, state).value;
      ref<Expr> result = SleExpr::create(left, right);
      bindLocal(ki, state, result);
      break;
    }

    default:
      terminateStateOnExecError(state, "invalid ICmp predicate");
    }
    break;
  }
 
    // Memory instructions...
  case Instruction::Alloca: {
    AllocaInst *ai = cast<AllocaInst>(i);
    unsigned elementSize = 
      kmodule->targetData->getTypeStoreSize(ai->getAllocatedType());
    ref<Expr> size = Expr::createPointer(elementSize);
    if (ai->isArrayAllocation()) {
      ref<Expr> count = eval(ki, 0, state).value;
      count = Expr::createZExtToPointerWidth(count);
      size = MulExpr::create(size, count);
    }
    executeAlloc(state, size, true, ki);
    break;
  }

  case Instruction::Load: {
    ref<Expr> base = eval(ki, 0, state).value;
    executeMemoryOperation(state, false, base, 0, ki);
    break;
  }
  case Instruction::Store: {
    ref<Expr> base = eval(ki, 1, state).value;
    ref<Expr> value = eval(ki, 0, state).value;
    //executeMemoryOperation(state, true, base, value, 0);
    executeMemoryOperation(state, true, base, value, ki);
    break;
  }

  case Instruction::GetElementPtr: {
    KGEPInstruction *kgepi = static_cast<KGEPInstruction*>(ki);
    ref<Expr> base = eval(ki, 0, state).value;
    state.getElmntPtrBases[ki->inst] = base;

    for (std::vector< std::pair<unsigned, uint64_t> >::iterator 
           it = kgepi->indices.begin(), ie = kgepi->indices.end(); 
         it != ie; ++it) {
      uint64_t elementSize = it->second;
      ref<Expr> index = eval(ki, it->first, state).value;
      base = AddExpr::create(base,
                             MulExpr::create(Expr::createSExtToPointerWidth(index),
                                             Expr::createPointer(elementSize)));
    }
    if (kgepi->offset)
      base = AddExpr::create(base,
                             Expr::createPointer(kgepi->offset));
    bindLocal(ki, state, base);
    break;
  }

    // Conversion
  case Instruction::Trunc: {
    CastInst *ci = cast<CastInst>(i);
    ref<Expr> result = ExtractExpr::create(eval(ki, 0, state).value,
                                           0,
                                           getWidthForLLVMType(ci->getType()));
    bindLocal(ki, state, result);
    break;
  }
  case Instruction::ZExt: {
    CastInst *ci = cast<CastInst>(i);
    ref<Expr> result = ZExtExpr::create(eval(ki, 0, state).value,
                                        getWidthForLLVMType(ci->getType()));
    bindLocal(ki, state, result);
    break;
  }
  case Instruction::SExt: {
    CastInst *ci = cast<CastInst>(i);
    ref<Expr> result = SExtExpr::create(eval(ki, 0, state).value,
                                        getWidthForLLVMType(ci->getType()));
    bindLocal(ki, state, result);
    break;
  }

  case Instruction::IntToPtr: {
    CastInst *ci = cast<CastInst>(i);
    Expr::Width pType = getWidthForLLVMType(ci->getType());
    ref<Expr> arg = eval(ki, 0, state).value;
    bindLocal(ki, state, ZExtExpr::create(arg, pType));
    break;
  } 
  case Instruction::PtrToInt: {
    CastInst *ci = cast<CastInst>(i);
    Expr::Width iType = getWidthForLLVMType(ci->getType());
    ref<Expr> arg = eval(ki, 0, state).value;
    bindLocal(ki, state, ZExtExpr::create(arg, iType));
    break;
  }

  case Instruction::BitCast: {
    ref<Expr> result = eval(ki, 0, state).value;
    bindLocal(ki, state, result);
    break;
  }

    // Floating point instructions

  case Instruction::FAdd: {
    ref<ConstantExpr> left = toConstant(state, eval(ki, 0, state).value,
                                        "floating point");
    ref<ConstantExpr> right = toConstant(state, eval(ki, 1, state).value,
                                         "floating point");
    if (!fpWidthToSemantics(left->getWidth()) ||
        !fpWidthToSemantics(right->getWidth()))
      return terminateStateOnExecError(state, "Unsupported FAdd operation");

#if LLVM_VERSION_CODE >= LLVM_VERSION(3, 3)
    llvm::APFloat Res(*fpWidthToSemantics(left->getWidth()), left->getAPValue());
    Res.add(APFloat(*fpWidthToSemantics(right->getWidth()),right->getAPValue()), APFloat::rmNearestTiesToEven);
#else
    llvm::APFloat Res(left->getAPValue());
    Res.add(APFloat(right->getAPValue()), APFloat::rmNearestTiesToEven);
#endif
    bindLocal(ki, state, ConstantExpr::alloc(Res.bitcastToAPInt()));
    break;
  }

  case Instruction::FSub: {
    ref<ConstantExpr> left = toConstant(state, eval(ki, 0, state).value,
                                        "floating point");
    ref<ConstantExpr> right = toConstant(state, eval(ki, 1, state).value,
                                         "floating point");
    if (!fpWidthToSemantics(left->getWidth()) ||
        !fpWidthToSemantics(right->getWidth()))
      return terminateStateOnExecError(state, "Unsupported FSub operation");
#if LLVM_VERSION_CODE >= LLVM_VERSION(3, 3)
    llvm::APFloat Res(*fpWidthToSemantics(left->getWidth()), left->getAPValue());
    Res.subtract(APFloat(*fpWidthToSemantics(right->getWidth()), right->getAPValue()), APFloat::rmNearestTiesToEven);
#else
    llvm::APFloat Res(left->getAPValue());
    Res.subtract(APFloat(right->getAPValue()), APFloat::rmNearestTiesToEven);
#endif
    bindLocal(ki, state, ConstantExpr::alloc(Res.bitcastToAPInt()));
    break;
  }
 
  case Instruction::FMul: {
    ref<ConstantExpr> left = toConstant(state, eval(ki, 0, state).value,
                                        "floating point");
    ref<ConstantExpr> right = toConstant(state, eval(ki, 1, state).value,
                                         "floating point");
    if (!fpWidthToSemantics(left->getWidth()) ||
        !fpWidthToSemantics(right->getWidth()))
      return terminateStateOnExecError(state, "Unsupported FMul operation");

#if LLVM_VERSION_CODE >= LLVM_VERSION(3, 3)
    llvm::APFloat Res(*fpWidthToSemantics(left->getWidth()), left->getAPValue());
    Res.multiply(APFloat(*fpWidthToSemantics(right->getWidth()), right->getAPValue()), APFloat::rmNearestTiesToEven);
#else
    llvm::APFloat Res(left->getAPValue());
    Res.multiply(APFloat(right->getAPValue()), APFloat::rmNearestTiesToEven);
#endif
    bindLocal(ki, state, ConstantExpr::alloc(Res.bitcastToAPInt()));
    break;
  }

  case Instruction::FDiv: {
    ref<ConstantExpr> left = toConstant(state, eval(ki, 0, state).value,
                                        "floating point");
    ref<ConstantExpr> right = toConstant(state, eval(ki, 1, state).value,
                                         "floating point");
    if (!fpWidthToSemantics(left->getWidth()) ||
        !fpWidthToSemantics(right->getWidth()))
      return terminateStateOnExecError(state, "Unsupported FDiv operation");

#if LLVM_VERSION_CODE >= LLVM_VERSION(3, 3)
    llvm::APFloat Res(*fpWidthToSemantics(left->getWidth()), left->getAPValue());
    Res.divide(APFloat(*fpWidthToSemantics(right->getWidth()), right->getAPValue()), APFloat::rmNearestTiesToEven);
#else
    llvm::APFloat Res(left->getAPValue());
    Res.divide(APFloat(right->getAPValue()), APFloat::rmNearestTiesToEven);
#endif
    bindLocal(ki, state, ConstantExpr::alloc(Res.bitcastToAPInt()));
    break;
  }

  case Instruction::FRem: {
    ref<ConstantExpr> left = toConstant(state, eval(ki, 0, state).value,
                                        "floating point");
    ref<ConstantExpr> right = toConstant(state, eval(ki, 1, state).value,
                                         "floating point");
    if (!fpWidthToSemantics(left->getWidth()) ||
        !fpWidthToSemantics(right->getWidth()))
      return terminateStateOnExecError(state, "Unsupported FRem operation");
#if LLVM_VERSION_CODE >= LLVM_VERSION(3, 3)
    llvm::APFloat Res(*fpWidthToSemantics(left->getWidth()), left->getAPValue());
    Res.mod(APFloat(*fpWidthToSemantics(right->getWidth()),right->getAPValue()),
            APFloat::rmNearestTiesToEven);
#else
    llvm::APFloat Res(left->getAPValue());
    Res.mod(APFloat(right->getAPValue()), APFloat::rmNearestTiesToEven);
#endif
    bindLocal(ki, state, ConstantExpr::alloc(Res.bitcastToAPInt()));
    break;
  }

  case Instruction::FPTrunc: {
    FPTruncInst *fi = cast<FPTruncInst>(i);
    Expr::Width resultType = getWidthForLLVMType(fi->getType());
    ref<ConstantExpr> arg = toConstant(state, eval(ki, 0, state).value,
                                       "floating point");
    if (!fpWidthToSemantics(arg->getWidth()) || resultType > arg->getWidth())
      return terminateStateOnExecError(state, "Unsupported FPTrunc operation");

#if LLVM_VERSION_CODE >= LLVM_VERSION(3, 3)
    llvm::APFloat Res(*fpWidthToSemantics(arg->getWidth()), arg->getAPValue());
#else
    llvm::APFloat Res(arg->getAPValue());
#endif
    bool losesInfo = false;
    Res.convert(*fpWidthToSemantics(resultType),
                llvm::APFloat::rmNearestTiesToEven,
                &losesInfo);
    bindLocal(ki, state, ConstantExpr::alloc(Res));
    break;
  }

  case Instruction::FPExt: {
    FPExtInst *fi = cast<FPExtInst>(i);
    Expr::Width resultType = getWidthForLLVMType(fi->getType());
    ref<ConstantExpr> arg = toConstant(state, eval(ki, 0, state).value,
                                        "floating point");
    if (!fpWidthToSemantics(arg->getWidth()) || arg->getWidth() > resultType)
      return terminateStateOnExecError(state, "Unsupported FPExt operation");
#if LLVM_VERSION_CODE >= LLVM_VERSION(3, 3)
    llvm::APFloat Res(*fpWidthToSemantics(arg->getWidth()), arg->getAPValue());
#else
    llvm::APFloat Res(arg->getAPValue());
#endif
    bool losesInfo = false;
    Res.convert(*fpWidthToSemantics(resultType),
                llvm::APFloat::rmNearestTiesToEven,
                &losesInfo);
    bindLocal(ki, state, ConstantExpr::alloc(Res));
    break;
  }

  case Instruction::FPToUI: {
    FPToUIInst *fi = cast<FPToUIInst>(i);
    Expr::Width resultType = getWidthForLLVMType(fi->getType());
    ref<ConstantExpr> arg = toConstant(state, eval(ki, 0, state).value,
                                       "floating point");
    if (!fpWidthToSemantics(arg->getWidth()) || resultType > 64)
      return terminateStateOnExecError(state, "Unsupported FPToUI operation");

#if LLVM_VERSION_CODE >= LLVM_VERSION(3, 3)
    llvm::APFloat Arg(*fpWidthToSemantics(arg->getWidth()), arg->getAPValue());
#else
    llvm::APFloat Arg(arg->getAPValue());
#endif
    uint64_t value = 0;
    bool isExact = true;
    Arg.convertToInteger(&value, resultType, false,
                         llvm::APFloat::rmTowardZero, &isExact);
    bindLocal(ki, state, ConstantExpr::alloc(value, resultType));
    break;
  }

  case Instruction::FPToSI: {
    FPToSIInst *fi = cast<FPToSIInst>(i);
    Expr::Width resultType = getWidthForLLVMType(fi->getType());
    ref<ConstantExpr> arg = toConstant(state, eval(ki, 0, state).value,
                                       "floating point");
    if (!fpWidthToSemantics(arg->getWidth()) || resultType > 64)
      return terminateStateOnExecError(state, "Unsupported FPToSI operation");
#if LLVM_VERSION_CODE >= LLVM_VERSION(3, 3)
    llvm::APFloat Arg(*fpWidthToSemantics(arg->getWidth()), arg->getAPValue());
#else
    llvm::APFloat Arg(arg->getAPValue());

#endif
    uint64_t value = 0;
    bool isExact = true;
    Arg.convertToInteger(&value, resultType, true,
                         llvm::APFloat::rmTowardZero, &isExact);
    bindLocal(ki, state, ConstantExpr::alloc(value, resultType));
    break;
  }

  case Instruction::UIToFP: {
    UIToFPInst *fi = cast<UIToFPInst>(i);
    Expr::Width resultType = getWidthForLLVMType(fi->getType());
    ref<ConstantExpr> arg = toConstant(state, eval(ki, 0, state).value,
                                       "floating point");
    const llvm::fltSemantics *semantics = fpWidthToSemantics(resultType);
    if (!semantics)
      return terminateStateOnExecError(state, "Unsupported UIToFP operation");
    llvm::APFloat f(*semantics, 0);
    f.convertFromAPInt(arg->getAPValue(), false,
                       llvm::APFloat::rmNearestTiesToEven);

    bindLocal(ki, state, ConstantExpr::alloc(f));
    break;
  }

  case Instruction::SIToFP: {
    SIToFPInst *fi = cast<SIToFPInst>(i);
    Expr::Width resultType = getWidthForLLVMType(fi->getType());
    ref<ConstantExpr> arg = toConstant(state, eval(ki, 0, state).value,
                                       "floating point");
    const llvm::fltSemantics *semantics = fpWidthToSemantics(resultType);
    if (!semantics)
      return terminateStateOnExecError(state, "Unsupported SIToFP operation");
    llvm::APFloat f(*semantics, 0);
    f.convertFromAPInt(arg->getAPValue(), true,
                       llvm::APFloat::rmNearestTiesToEven);

    bindLocal(ki, state, ConstantExpr::alloc(f));
    break;
  }

  case Instruction::FCmp: {
    FCmpInst *fi = cast<FCmpInst>(i);
    ref<ConstantExpr> left = toConstant(state, eval(ki, 0, state).value,
                                        "floating point");
    ref<ConstantExpr> right = toConstant(state, eval(ki, 1, state).value,
                                         "floating point");
    if (!fpWidthToSemantics(left->getWidth()) ||
        !fpWidthToSemantics(right->getWidth()))
      return terminateStateOnExecError(state, "Unsupported FCmp operation");

#if LLVM_VERSION_CODE >= LLVM_VERSION(3, 3)
    APFloat LHS(*fpWidthToSemantics(left->getWidth()),left->getAPValue());
    APFloat RHS(*fpWidthToSemantics(right->getWidth()),right->getAPValue());
#else
    APFloat LHS(left->getAPValue());
    APFloat RHS(right->getAPValue());
#endif
    APFloat::cmpResult CmpRes = LHS.compare(RHS);

    bool Result = false;
    switch( fi->getPredicate() ) {
      // Predicates which only care about whether or not the operands are NaNs.
    case FCmpInst::FCMP_ORD:
      Result = CmpRes != APFloat::cmpUnordered;
      break;

    case FCmpInst::FCMP_UNO:
      Result = CmpRes == APFloat::cmpUnordered;
      break;

      // Ordered comparisons return false if either operand is NaN.  Unordered
      // comparisons return true if either operand is NaN.
    case FCmpInst::FCMP_UEQ:
      if (CmpRes == APFloat::cmpUnordered) {
        Result = true;
        break;
      }
    case FCmpInst::FCMP_OEQ:
      Result = CmpRes == APFloat::cmpEqual;
      break;

    case FCmpInst::FCMP_UGT:
      if (CmpRes == APFloat::cmpUnordered) {
        Result = true;
        break;
      }
    case FCmpInst::FCMP_OGT:
      Result = CmpRes == APFloat::cmpGreaterThan;
      break;

    case FCmpInst::FCMP_UGE:
      if (CmpRes == APFloat::cmpUnordered) {
        Result = true;
        break;
      }
    case FCmpInst::FCMP_OGE:
      Result = CmpRes == APFloat::cmpGreaterThan || CmpRes == APFloat::cmpEqual;
      break;

    case FCmpInst::FCMP_ULT:
      if (CmpRes == APFloat::cmpUnordered) {
        Result = true;
        break;
      }
    case FCmpInst::FCMP_OLT:
      Result = CmpRes == APFloat::cmpLessThan;
      break;

    case FCmpInst::FCMP_ULE:
      if (CmpRes == APFloat::cmpUnordered) {
        Result = true;
        break;
      }
    case FCmpInst::FCMP_OLE:
      Result = CmpRes == APFloat::cmpLessThan || CmpRes == APFloat::cmpEqual;
      break;

    case FCmpInst::FCMP_UNE:
      Result = CmpRes == APFloat::cmpUnordered || CmpRes != APFloat::cmpEqual;
      break;
    case FCmpInst::FCMP_ONE:
      Result = CmpRes != APFloat::cmpUnordered && CmpRes != APFloat::cmpEqual;
      break;

    default:
      assert(0 && "Invalid FCMP predicate!");
    case FCmpInst::FCMP_FALSE:
      Result = false;
      break;
    case FCmpInst::FCMP_TRUE:
      Result = true;
      break;
    }

    bindLocal(ki, state, ConstantExpr::alloc(Result, Expr::Bool));
    break;
  }
 case Instruction::InsertValue: {
    KGEPInstruction *kgepi = static_cast<KGEPInstruction*>(ki);

    ref<Expr> agg = eval(ki, 0, state).value;
    ref<Expr> val = eval(ki, 1, state).value;

    ref<Expr> l = NULL, r = NULL;
    unsigned lOffset = kgepi->offset*8, rOffset = kgepi->offset*8 + val->getWidth();

    if (lOffset > 0)
      l = ExtractExpr::create(agg, 0, lOffset);
    if (rOffset < agg->getWidth())
      r = ExtractExpr::create(agg, rOffset, agg->getWidth() - rOffset);

    ref<Expr> result;
    if (!l.isNull() && !r.isNull())
      result = ConcatExpr::create(r, ConcatExpr::create(val, l));
    else if (!l.isNull())
      result = ConcatExpr::create(val, l);
    else if (!r.isNull())
      result = ConcatExpr::create(r, val);
    else
      result = val;

    bindLocal(ki, state, result);
    break;
  }
 case Instruction::ExtractValue: {
    KGEPInstruction *kgepi = static_cast<KGEPInstruction*>(ki);

    ref<Expr> agg = eval(ki, 0, state).value;

    ref<Expr> result = ExtractExpr::create(agg, kgepi->offset*8, getWidthForLLVMType(i->getType()));

    bindLocal(ki, state, result);
    break;
  }
#if LLVM_VERSION_CODE >= LLVM_VERSION(3, 3)
  case Instruction::Fence: {
    // Ignore for now
    break;
  }
#endif

  // Other instructions...
  // Unhandled
  case Instruction::ExtractElement:
  case Instruction::InsertElement:
  case Instruction::ShuffleVector:
    terminateStateOnError(state, "XXX vector instructions unhandled",
                          Unhandled);
    break;
 
  default:
    terminateStateOnExecError(state, "illegal instruction");
    break;
  }
}

void Executor::updateStates(ExecutionState *current) {
  if (searcher) {
    searcher->update(current, addedStates, removedStates);
  }
  
  states.insert(addedStates.begin(), addedStates.end());
  addedStates.clear();

  for (std::vector<ExecutionState *>::iterator it = removedStates.begin(),
                                               ie = removedStates.end();
       it != ie; ++it) {
    ExecutionState *es = *it;
    std::set<ExecutionState*>::iterator it2 = states.find(es);
    assert(it2!=states.end());
    states.erase(it2);
    std::map<ExecutionState*, std::vector<SeedInfo> >::iterator it3 = 
      seedMap.find(es);
    if (it3 != seedMap.end())
      seedMap.erase(it3);
    processTree->remove(es->ptreeNode);
    delete es;
  }
  removedStates.clear();
}

template <typename TypeIt>
void Executor::computeOffsets(KGEPInstruction *kgepi, TypeIt ib, TypeIt ie) {
  ref<ConstantExpr> constantOffset =
    ConstantExpr::alloc(0, Context::get().getPointerWidth());
  uint64_t index = 1;
  for (TypeIt ii = ib; ii != ie; ++ii) {
    if (LLVM_TYPE_Q StructType *st = dyn_cast<StructType>(*ii)) {
      const StructLayout *sl = kmodule->targetData->getStructLayout(st);
      const ConstantInt *ci = cast<ConstantInt>(ii.getOperand());
      uint64_t addend = sl->getElementOffset((unsigned) ci->getZExtValue());
      constantOffset = constantOffset->Add(ConstantExpr::alloc(addend,
                                                               Context::get().getPointerWidth()));
    } else {
      const SequentialType *set = cast<SequentialType>(*ii);
      uint64_t elementSize = 
        kmodule->targetData->getTypeStoreSize(set->getElementType());
      Value *operand = ii.getOperand();
      if (Constant *c = dyn_cast<Constant>(operand)) {
        ref<ConstantExpr> index = 
          evalConstant(c)->SExt(Context::get().getPointerWidth());
        ref<ConstantExpr> addend = 
          index->Mul(ConstantExpr::alloc(elementSize,
                                         Context::get().getPointerWidth()));
        constantOffset = constantOffset->Add(addend);
      } else {
        kgepi->indices.push_back(std::make_pair(index, elementSize));
      }
    }
    index++;
  }
  kgepi->offset = constantOffset->getZExtValue();
}

void Executor::bindInstructionConstants(KInstruction *KI) {
  KGEPInstruction *kgepi = static_cast<KGEPInstruction*>(KI);

  if (GetElementPtrInst *gepi = dyn_cast<GetElementPtrInst>(KI->inst)) {
    computeOffsets(kgepi, gep_type_begin(gepi), gep_type_end(gepi));
  } else if (InsertValueInst *ivi = dyn_cast<InsertValueInst>(KI->inst)) {
    computeOffsets(kgepi, iv_type_begin(ivi), iv_type_end(ivi));
    assert(kgepi->indices.empty() && "InsertValue constant offset expected");
  } else if (ExtractValueInst *evi = dyn_cast<ExtractValueInst>(KI->inst)) {
    computeOffsets(kgepi, ev_type_begin(evi), ev_type_end(evi));
    assert(kgepi->indices.empty() && "ExtractValue constant offset expected");
  }
}

void Executor::bindModuleConstants() {
  for (std::vector<KFunction*>::iterator it = kmodule->functions.begin(), 
         ie = kmodule->functions.end(); it != ie; ++it) {
    KFunction *kf = *it;
    for (unsigned i=0; i<kf->numInstructions; ++i)
      bindInstructionConstants(kf->instructions[i]);
  }

  kmodule->constantTable = new Cell[kmodule->constants.size()];
  for (unsigned i=0; i<kmodule->constants.size(); ++i) {
    Cell &c = kmodule->constantTable[i];
    c.value = evalConstant(kmodule->constants[i]);
  }
}

void Executor::checkMemoryUsage() {
  if (!MaxMemory)
    return;
  if ((stats::instructions & 0xFFFF) == 0) {
    // We need to avoid calling GetTotalMallocUsage() often because it
    // is O(elts on freelist). This is really bad since we start
    // to pummel the freelist once we hit the memory cap.
    unsigned mbs = (util::GetTotalMallocUsage() >> 20) +
                   (memory->getUsedDeterministicSize() >> 20);

    if (mbs > MaxMemory) {
      if (mbs > MaxMemory + 100) {
        // just guess at how many to kill
        unsigned numStates = states.size();
        unsigned toKill = std::max(1U, numStates - numStates * MaxMemory / mbs);
        klee_warning("killing %d states (over memory cap)", toKill);
        std::vector<ExecutionState *> arr(states.begin(), states.end());
        for (unsigned i = 0, N = arr.size(); N && i < toKill; ++i, --N) {
          unsigned idx = rand() % N;
          // Make two pulls to try and not hit a state that
          // covered new code.
          if (arr[idx]->coveredNew)
            idx = rand() % N;

          std::swap(arr[idx], arr[N - 1]);
          terminateStateEarly(*arr[N - 1], "Memory limit exceeded.");
        }
      }
      atMemoryLimit = true;
    } else {
      atMemoryLimit = false;
    }
  }
}

void Executor::doDumpStates() {
  if (!DumpStatesOnHalt || states.empty())
    return;
  klee_message("halting execution, dumping remaining states");
  for (std::set<ExecutionState *>::iterator it = states.begin(),
                                            ie = states.end();
       it != ie; ++it) {
    ExecutionState &state = **it;
    stepInstruction(state); // keep stats rolling
    terminateStateEarly(state, "Execution halting.");
  }
  updateStates(0);
}

void Executor::run(ExecutionState &initialState) {
  bindModuleConstants();

  // Delay init till now so that ticks don't accrue during
  // optimization and such.
  initTimers();

  states.insert(&initialState);

  (*debugHeapFile) << "KLEE " << (usingSeeds ? "IS" : "IS NOT") << " using seeds \n";
  
  if (usingSeeds) {
    std::vector<SeedInfo> &v = seedMap[&initialState];
    
    for (std::vector<KTest*>::const_iterator it = usingSeeds->begin(), 
           ie = usingSeeds->end(); it != ie; ++it)
      v.push_back(SeedInfo(*it));

    int lastNumSeeds = usingSeeds->size()+10;
    double lastTime, startTime = lastTime = util::getWallTime();
    ExecutionState *lastState = 0;
    while (!seedMap.empty()) {
      if (haltExecution) {
        doDumpStates();
        return;
      }

      std::map<ExecutionState*, std::vector<SeedInfo> >::iterator it = 
        seedMap.upper_bound(lastState);
      if (it == seedMap.end())
        it = seedMap.begin();
      lastState = it->first;
      unsigned numSeeds = it->second.size();
      ExecutionState &state = *lastState;
      KInstruction *ki = state.pc;
      stepInstruction(state);

      executeInstruction(state, ki);
      processTimers(&state, MaxInstructionTime * numSeeds);
      updateStates(&state);

      if ((stats::instructions % 1000) == 0) {
        int numSeeds = 0, numStates = 0;
        for (std::map<ExecutionState*, std::vector<SeedInfo> >::iterator
               it = seedMap.begin(), ie = seedMap.end();
             it != ie; ++it) {
          numSeeds += it->second.size();
          numStates++;
        }
        double time = util::getWallTime();
        if (SeedTime>0. && time > startTime + SeedTime) {
          klee_warning("seed time expired, %d seeds remain over %d states",
                       numSeeds, numStates);
          break;
        } else if (numSeeds<=lastNumSeeds-10 ||
                   time >= lastTime+10) {
          lastTime = time;
          lastNumSeeds = numSeeds;          
          klee_message("%d seeds remaining over: %d states", 
                       numSeeds, numStates);
        }
      }
    }

    klee_message("seeding done (%d states remain)", (int) states.size());

    // XXX total hack, just because I like non uniform better but want
    // seed results to be equally weighted.
    for (std::set<ExecutionState*>::iterator
           it = states.begin(), ie = states.end();
         it != ie; ++it) {
      (*it)->weight = 1.;
    }

    if (OnlySeed) {
      doDumpStates();
      return;
    }
  }

  searcher = constructUserSearcher(*this);

  std::vector<ExecutionState *> newStates(states.begin(), states.end());
  searcher->update(0, newStates, std::vector<ExecutionState *>());

  while (!states.empty() && !haltExecution) {
    ExecutionState &state = searcher->selectState();
    KInstruction *ki = state.pc;
    stepInstruction(state);

    executeInstruction(state, ki);
    processTimers(&state, MaxInstructionTime);

    checkMemoryUsage();

    updateStates(&state);
  }

  delete searcher;
  searcher = 0;

  doDumpStates();
}

std::string Executor::getAddressInfo(ExecutionState &state, 
                                     ref<Expr> address) const{
  std::string Str;
  llvm::raw_string_ostream info(Str);
  info << "\taddress: " << address << "\n";
  uint64_t example;
  if (ConstantExpr *CE = dyn_cast<ConstantExpr>(address)) {
    example = CE->getZExtValue();
  } else {
    ref<ConstantExpr> value;
    bool success = solver->getValue(state, address, value);
    assert(success && "FIXME: Unhandled solver failure");
    (void) success;
    example = value->getZExtValue();
    info << "\texample: " << example << "\n";


    // HKLEE: added.  This function is only used at state termination so its OK if we fail
    solver->setTimeout(coreSolverTimeout);
    bool timedout;
    std::pair< ref<Expr>, ref<Expr> > res = solver->getRange(state, address, timedout);
    solver->setTimeout(0);
    if (timedout)
      return (std::string("unknown: timed out"));
    
    info << "\trange: [" << res.first << ", " << res.second <<"]\n";
  }
  
  MemoryObject hack((unsigned) example);    
  MemoryMap::iterator lower = state.addressSpace.objects.upper_bound(&hack);
  info << "\tnext: ";
  if (lower==state.addressSpace.objects.end()) {
    info << "none\n";
  } else {
    const MemoryObject *mo = lower->first;
    std::string alloc_info;
    mo->getAllocInfo(alloc_info);
    info << "object at " << mo->guest_address()
         << " of size " << mo->size << "\n"
         << "\t\t" << alloc_info << "\n";
  }
  if (lower!=state.addressSpace.objects.begin()) {
    --lower;
    info << "\tprev: ";
    if (lower==state.addressSpace.objects.end()) {
      info << "none\n";
    } else {
      const MemoryObject *mo = lower->first;
      std::string alloc_info;
      mo->getAllocInfo(alloc_info);
      info << "object at " << mo->guest_address() 
           << " of size " << mo->size << "\n"
           << "\t\t" << alloc_info << "\n";
    }
  }

  return info.str();
}

void Executor::terminateState(ExecutionState &state) {
  if (replayKTest && replayPosition!=replayKTest->numObjects) {
    klee_warning_once(replayKTest,
                      "replay did not consume all objects in test input.");
  }

  interpreterHandler->incPathsExplored();

  std::vector<ExecutionState *>::iterator it =
      std::find(addedStates.begin(), addedStates.end(), &state);
  if (it==addedStates.end()) {
    state.pc = state.prevPC;

    removedStates.push_back(&state);
  } else {
    // never reached searcher, just delete immediately
    std::map< ExecutionState*, std::vector<SeedInfo> >::iterator it3 = 
      seedMap.find(&state);
    if (it3 != seedMap.end())
      seedMap.erase(it3);
    addedStates.erase(it);
    processTree->remove(state.ptreeNode);
    delete &state;
  }
}

void Executor::terminateStateEarly(ExecutionState &state, 
                                   const Twine &message) {
  if (!OnlyOutputStatesCoveringNew || state.coveredNew ||
      (AlwaysOutputSeeds && seedMap.count(&state)))
    interpreterHandler->processTestCase(state, (message + "\n").str().c_str(),
                                        "early");
  terminateState(state);
}

void Executor::terminateStateOnExit(ExecutionState &state) {
  if (!OnlyOutputStatesCoveringNew || state.coveredNew || 
      (AlwaysOutputSeeds && seedMap.count(&state)))
    interpreterHandler->processTestCase(state, 0, 0);
  terminateState(state);
}

const InstructionInfo & Executor::getLastNonKleeInternalInstruction(const ExecutionState &state,
    Instruction ** lastInstruction) {
  // unroll the stack of the applications state and find
  // the last instruction which is not inside a KLEE internal function
  ExecutionState::stack_ty::const_reverse_iterator it = state.stack.rbegin(),
      itE = state.stack.rend();

  // don't check beyond the outermost function (i.e. main())
  itE--;

  const InstructionInfo * ii = 0;
  if (kmodule->internalFunctions.count(it->kf->function) == 0){
    ii =  state.prevPC->info;
    *lastInstruction = state.prevPC->inst;
    //  Cannot return yet because even though
    //  it->function is not an internal function it might of
    //  been called from an internal function.
  }

  // Wind up the stack and check if we are in a KLEE internal function.
  // We visit the entire stack because we want to return a CallInstruction
  // that was not reached via any KLEE internal functions.
  for (;it != itE; ++it) {
    // check calling instruction and if it is contained in a KLEE internal function
    const Function * f = (*it->caller).inst->getParent()->getParent();
    if (kmodule->internalFunctions.count(f)){
      ii = 0;
      continue;
    }
    if (!ii){
      ii = (*it->caller).info;
      *lastInstruction = (*it->caller).inst;
    }
  }

  if (!ii) {
    // something went wrong, play safe and return the current instruction info
    *lastInstruction = state.prevPC->inst;
    return *state.prevPC->info;
  }
  return *ii;
}

bool Executor::shouldExitOn(enum TerminateReason termReason) {
  std::vector<TerminateReason>::iterator s = ExitOnErrorType.begin();
  std::vector<TerminateReason>::iterator e = ExitOnErrorType.end();

  for (; s != e; ++s)
    if (termReason == *s)
      return true;

  return false;
}

void Executor::terminateStateOnError(ExecutionState &state,
                                     const llvm::Twine &messaget,
                                     enum TerminateReason termReason,
                                     const char *suffix,
                                     const llvm::Twine &info) {
  std::string message = messaget.str();
  static std::set< std::pair<Instruction*, std::string> > emittedErrors;
  Instruction * lastInst;
  const InstructionInfo &ii = getLastNonKleeInternalInstruction(state, &lastInst);
  
  if (EmitAllErrors ||
      emittedErrors.insert(std::make_pair(lastInst, message)).second) {
    if (ii.file != "") {
      klee_message("ERROR: %s:%d: %s", ii.file.c_str(), ii.line, message.c_str());
    } else {
      klee_message("ERROR: (location information missing) %s", message.c_str());
    }
    if (!EmitAllErrors)
      klee_message("NOTE: now ignoring this error at this location");

    std::string MsgString;
    llvm::raw_string_ostream msg(MsgString);
    msg << "Error: " << message << "\n";
    if (ii.file != "") {
      msg << "File: " << ii.file << "\n";
      msg << "Line: " << ii.line << "\n";
      msg << "assembly.ll line: " << ii.assemblyLine << "\n";
    }
    msg << "Stack: \n";
    state.dumpStack(msg);

    std::string info_str = info.str();
    if (info_str != "")
      msg << "Info: \n" << info_str;

    std::string suffix_buf;
    if (!suffix) {
      suffix_buf = TerminateReasonNames[termReason];
      suffix_buf += ".err";
      suffix = suffix_buf.c_str();
    }

    interpreterHandler->processTestCase(state, msg.str().c_str(), suffix);
  }
    
  terminateState(state);

  if (shouldExitOn(termReason))
    haltExecution = true;
}

// XXX shoot me
static const char *okExternalsList[] = { "printf", 
                                         "fprintf", 
                                         "puts",
                                         "getpid" };
static std::set<std::string> okExternals(okExternalsList,
                                         okExternalsList + 
                                         (sizeof(okExternalsList)/sizeof(okExternalsList[0])));

void Executor::callExternalFunction(ExecutionState &state,
                                    KInstruction *target,
                                    Function *function,
                                    std::vector< ref<Expr> > &arguments) {
  // check if specialFunctionHandler wants it
  if (specialFunctionHandler->handle(state, function, target, arguments))
    return;
  
  if (NoExternals && !okExternals.count(function->getName())) {
    klee_warning("Disallowed call to external function: %s\n",
               function->getName().str().c_str());
    terminateStateOnError(state, "externals disallowed", User);
    return;
  }

  // normal external function handling path
  // allocate 128 bits for each argument (+return value) to support fp80's;
  // we could iterate through all the arguments first and determine the exact
  // size we need, but this is faster, and the memory usage isn't significant.
  uint64_t *args = (uint64_t*) alloca(2*sizeof(*args) * (arguments.size() + 1));
  memset(args, 0, 2 * sizeof(*args) * (arguments.size() + 1));
  unsigned wordIndex = 2;
  for (std::vector<ref<Expr> >::iterator ai = arguments.begin(), 
       ae = arguments.end(); ai!=ae; ++ai) {
    if (AllowExternalSymCalls) { // don't bother checking uniqueness
      ref<ConstantExpr> ce;
      bool success = solver->getValue(state, *ai, ce);
      assert(success && "FIXME: Unhandled solver failure");
      (void) success;
      ce->toMemory(&args[wordIndex]);
      wordIndex += (ce->getWidth()+63)/64;
    } else {
      ref<Expr> arg = toUnique(state, *ai);
      if (ConstantExpr *ce = dyn_cast<ConstantExpr>(arg)) {
        // XXX kick toMemory functions from here
        ce->toMemory(&args[wordIndex]);
        wordIndex += (ce->getWidth()+63)/64;
      } else {
        terminateStateOnExecError(state, 
                                  "external call with symbolic argument: " + 
                                  function->getName());
        return;
      }
    }
  }

  state.addressSpace.copyOutConcretes();

  if (!SuppressExternalWarnings) {

    std::string TmpStr;
    llvm::raw_string_ostream os(TmpStr);
    os << "calling external: " << function->getName().str() << "(";
    for (unsigned i=0; i<arguments.size(); i++) {
      os << arguments[i];
      if (i != arguments.size()-1)
	os << ", ";
    }
    os << ") at ";
    state.pc->printFileLine(os);
    
    if (AllExternalWarnings)
      klee_warning("%s", os.str().c_str());
    else
      klee_warning_once(function, "%s", os.str().c_str());
  }
  bool success = externalDispatcher->executeCall(function, target->inst, args);
  if (!success) {
    terminateStateOnError(state, "failed external call: " + function->getName(),
                          External);
    return;
  }

  if (!state.addressSpace.copyInConcretes()) {
    terminateStateOnError(state, "external modified read-only object",
                          External);
    return;
  }

  LLVM_TYPE_Q Type *resultType = target->inst->getType();
  if (resultType != Type::getVoidTy(function->getContext())) {
    ref<Expr> e = ConstantExpr::fromMemory((void*) args, 
                                           getWidthForLLVMType(resultType));
    bindLocal(target, state, e);
  }
}

/***/

ref<Expr> Executor::replaceReadWithSymbolic(ExecutionState &state, 
                                            ref<Expr> e) {
  unsigned n = interpreterOpts.MakeConcreteSymbolic;
  if (!n || replayKTest || replayPath)
    return e;

  // right now, we don't replace symbolics (is there any reason to?)
  if (!isa<ConstantExpr>(e))
    return e;

  if (n != 1 && random() % n)
    return e;

  // create a new fresh location, assert it is equal to concrete value in e
  // and return it.
  
  static unsigned id;
  const Array *array =
      arrayCache.CreateArray("rrws_arr" + llvm::utostr(++id),
                             Expr::getMinBytesForWidth(e->getWidth()));
  ref<Expr> res = Expr::createTempRead(array, e->getWidth());
  ref<Expr> eq = NotOptimizedExpr::create(EqExpr::create(e, res));
  (*debugHeapFile) << "Making symbolic: " << eq << "\n";
  state.addConstraint(eq);
  return res;
}

 ObjectState *Executor::bindObjectInState(ExecutionState &state, 
                                         const MemoryObject *mo,
                                         bool SaidIsLocal,
					  const Array *array) {
   ObjectState *os = array ? new ObjectState(mo, array) : new ObjectState(mo);
   state.addressSpace.bindObject(mo, os);

   /*** H-KLEE: fine grained tracking of memory objects */
   bool isSymbolic = array ? true : false;
   bool isFixed = mo->isFixed;
   bool isGlobal = mo->isGlobal;
   bool isLocal = mo->isLocal;

   if (isLocal != SaidIsLocal)
     klee_warning("Executor::bindObjectInState: isLocal and SaidIsLocal disagree (inconsistent object state)");
   if (isLocal == true && isGlobal == true)
     klee_warning("Object is both local and global (inconsistent object state)");
   
   if (isSymbolic) state.addressSpace.symbolic_obj_nbr++;
   if (isFixed) state.addressSpace.fixed_obj_nbr++;
   if (isGlobal) state.addressSpace.global_obj_nbr++;
   //if (isLocal) state.addressSpace.local_obj_nbr++;
   if (SaidIsLocal) state.addressSpace.local_obj_nbr++;     
   
  // Its possible that multiple bindings of the same mo in the state
  // will put multiple copies on this list, but it doesn't really
  // matter because all we use this list for is to unbind the object
  // on function return.
  if (SaidIsLocal)
    state.stack.back().allocas.push_back(mo);

  // Update numObjects in stats tracker
  statsTracker->updateNumObjects(state.addressSpace.objects.size());
  
  return os;
}


/* \brief Find the minimum value of <size> that satisfies the state's
 * constraints.

 * \description We start by any values which satisfies the state's
 * constraints, and then divide by 2 until the size is 0 or
 * constraints are not satisfied anymore 
 * 
 * \param state Execution state with constraints on size
 * \param size  The variable for which we look for the lower bound
 * \return Lower bound
 */
//ref<ConstantExpr> getLowerBound(ExecutionState &state,
uint64_t Executor::getLowerBound(ExecutionState &state, ref<Expr> size)
{
  /* Get the start value which satisfies the constraints */
  ref<ConstantExpr> value;
  bool res, success;
  success = solver->getValue(state, size, value);
  //llvm::outs() << "Executor::getLowerBound(): fell back to custom binary search\n";
  assert(success && "FIXME: Unhandled solver failure");
  (void) success;
  Expr::Width W = value->getWidth();
  ref<ConstantExpr> tmp;
  
  /* Binary search */
  ref<ConstantExpr> L = ConstantExpr::alloc(0, W);
  ref<ConstantExpr> R = value;
  int counter = 0;
  while (L->Ult(R)->isTrue())
  {
    counter++;
    //llvm::outs() << "\nExecutor::getLowerBound(): loop iteration " << counter << ", L = " << L << ", R = " << R << "\n";
    tmp = (L->Add(R))->LShr(ConstantExpr::alloc(1, W)); /* tmp = (L+R)/2 */
    success = solver->mayBeTrue(state, EqExpr::create(tmp, size), res);
    assert(success && "FIXME: Unhandled solver failure");      
    (void) success;
    if(res)
    {
      //llvm::outs() << "Executor::getLowerBound(): tmp =  " << tmp << " satisfies the conds\n";
      value = tmp;
      R = tmp->Sub(ConstantExpr::alloc(1, W));
    }
    else
    {
      //llvm::outs() << "Executor::getLowerBound(): tmp =  " << tmp << " does not satisfy the conds\n";
      L = tmp->Add(ConstantExpr::alloc(1, W));
    }
    //llvm::outs() << "Executor::getLowerBound(): loop iteration " << counter << ", L = " << L << ", R = " << R << "\n";
  }
  success = solver->mayBeTrue(state, EqExpr::create(L, size), res);
  assert(success && "FIXME: Unhandled solver failure");      
  if(res)
    value = L;
  return value->getZExtValue();
}


// JV: used to remember edges in the state space on single branch
 void Executor::trackEdges(ExecutionState& orig_state, ExecutionState& dest_state, int edge_type, std::string edge_label)
 {
   //std::string orig_statename  = ToString(orig_state.id);
   std::string orig_sym_statename  = ToString(orig_state.last_sym_state_id);
   //std::string orig_heap_statename  = ToString(orig_state.last_heap_state_id);
   
   switch (edge_type)
     {

       // Edges of the state space
     case EDGE_SYM:
       dest_state.id = this->next_state_id++;
       dest_state.last_heap_state_id = orig_state.last_heap_state_id;
       dest_state.last_sym_state_id = dest_state.id;
       std::string dest_statename  = ToString(dest_state.id);
       SymStates[dest_statename] = std::make_pair(false,"");
       StringPair fpair = std::make_pair(orig_sym_statename, dest_statename);
       if (SymEdges.count(fpair) == 0)
	 SymEdges[fpair] = edge_label;
       return;
       break;
       
       // Heap Space transitions : Case is currently not used in this context
       /*
	 case EDGE_HEAP:
	 dest_state->id = this->next_state_id++;
	 std::string dest_statename  = ToString(dest_state->id);
	 HeapStates.push_back(dest_statename);
	 StringPair fpair = std::make_pair(orig_statename, dest_statename);
	 if (HeapEdges.count(fpair) == 0)
	 HeapEdges[fpair] = "";
	 break;
       */
       //default:
       //break;
     }
       
   assert(false && "Unknown branch edge type - exiting \n");
 }
 
// JV: used to remember edges in the state space on fork
 void Executor::trackEdges(ExecutionState& orig_state,
			   StatePair& spair,
			   int edge_type,
			   std::string edge_label)
 {
   std::string orig_sym_statename  = ToString(orig_state.last_sym_state_id);
   std::string orig_heap_statename  = ToString(orig_state.last_heap_state_id);

   switch (edge_type)
     {

       // Edges of the (non heap) symbolic state space
     case EDGE_SYM:
       if (spair.first)
	 {
	   spair.first->id = this->next_state_id++;
	   spair.first->last_heap_state_id = orig_state.last_heap_state_id;
	   spair.first->last_sym_state_id = spair.first->id;
	   
	   std::string left_statename  = ToString(spair.first->id);
	   SymStates[left_statename] = std::make_pair(false,"");
	   StringPair fpair = std::make_pair(orig_sym_statename, left_statename);
	   if (SymEdges.count(fpair) == 0)
	     SymEdges[fpair] = edge_label;
	 }       
       if (spair.second)
	 {
	   spair.second->id = this->next_state_id++;
	   spair.second->last_heap_state_id = orig_state.last_heap_state_id;
	   spair.second->last_sym_state_id = spair.second->id;
	   
	   std::string right_statename = ToString(spair.second->id);
	   SymStates[right_statename] = std::make_pair(false,"");
	   StringPair fpair = std::make_pair(orig_sym_statename, right_statename);
	   if (SymEdges.count(fpair) == 0)
	     SymEdges[fpair] = edge_label;         
	 }
       break;

       // The actual interesting thing: edges of the heap space
     case EDGE_HEAP:
       if (spair.first)
	 {
	   spair.first->id = this->next_state_id++;
	   spair.first->last_heap_state_id = spair.first->id;
	   spair.first->last_sym_state_id = orig_state.last_sym_state_id; 
	   
	   std::string left_state_name  = ToString(spair.first->id);
	   std::string left_state_parent = spair.first->parentFunction();

	   std::string llocal_objnum = ToString(spair.first->addressSpace.local_obj_nbr);
	   std::string lglobal_objnum = ToString(spair.first->addressSpace.global_obj_nbr);
	   std::string lfixed_objnum = ToString(spair.first->addressSpace.fixed_obj_nbr);
	   std::string lsym_objnum = ToString(spair.first->addressSpace.symbolic_obj_nbr);
	   std::string ltotal_objnum = ToString(spair.first->ObjectNbr());
	   std::string lstate_objnum = "(" + ltotal_objnum + "=(" + lglobal_objnum + "G," +
	     llocal_objnum + "L)," + lsym_objnum + "S," + lfixed_objnum + "F)";
	   
	   std::string left_state_constnum = ToString(spair.first->constraints.size()) + "C";
	   std::string left_state_label = left_state_parent + "," + lstate_objnum +
	     "," + left_state_constnum;
	   
	   HeapStates[left_state_name] = std::make_pair(false,left_state_label);
	   
	   StringPair fpair = std::make_pair(orig_heap_statename, left_state_name);
	   if (HeapEdges.count(fpair) == 0)
	     HeapEdges[fpair] = edge_label;
	 }       
       if (spair.second)
	 {
	   spair.second->id = this->next_state_id++;
	   spair.second->last_heap_state_id = spair.second->id;
	   spair.second->last_sym_state_id = orig_state.last_sym_state_id; 

	   std::string right_state_name  = ToString(spair.second->id);
	   std::string right_state_parent = spair.second->parentFunction();

	   std::string rlocal_objnum = ToString(spair.second->addressSpace.local_obj_nbr);
	   std::string rglobal_objnum = ToString(spair.second->addressSpace.global_obj_nbr);
	   std::string rfixed_objnum = ToString(spair.second->addressSpace.fixed_obj_nbr);
	   std::string rsym_objnum = ToString(spair.second->addressSpace.symbolic_obj_nbr);
	   std::string rtotal_objnum = ToString(spair.second->ObjectNbr());
	   std::string rstate_objnum = "(" + rtotal_objnum + "=(" +
	     rglobal_objnum + "g," + rlocal_objnum + "l)," + rsym_objnum + "s," + rfixed_objnum + "f)";
	   
	   std::string right_state_constnum = ToString(spair.second->constraints.size()) + "c";
	   std::string right_state_label = right_state_parent + "," + rstate_objnum + "," + right_state_constnum;
	   HeapStates[right_state_name] = std::make_pair(false,right_state_label);
	   
	   StringPair fpair = std::make_pair(orig_heap_statename, right_state_name);
	   if (HeapEdges.count(fpair) == 0)
	     HeapEdges[fpair] = edge_label;         
	 }
       break;

     default:
       assert(false && "Unknown fork edge type - exiting \n");       
     }
   
 }


 
void Executor::executeAlloc(ExecutionState &state,
                            ref<Expr> size,
                            bool isLocal,
                            KInstruction *target,
                            bool zeroMemory,
                            const ObjectState *reallocFrom) {

  // JV: This looks incorrect - it will force conversion to a ConstantExpr, we want to do this after the cast below.
  size = toUnique(state, size);
  
  /* When the size is constant */
  MemoryObject *mo;
  ConstantExpr *CE = dyn_cast<ConstantExpr>(size);

  /* Track how many allocations were symbolic and how many were of constant size */

  /* This counts the numbe of calls with symbolic size rather than the number of locations, so we enable this
     anyway. Ideally we would want to have a different counter for symbolic reallocation.
     
     //if (statsTracker && !(!target && reallocFrom)) // Don't count when we just resize dynamic objects  
  */
  
  statsTracker->memAllocated((CE == NULL ? false : true));

  if (CE)
  {
      mo = memory->allocate(CE->getZExtValue(), isLocal, false,
			    state.prevPC->inst);

      //llvm::outs() << " FOUND MALLOC WITH CONCRETE SIZE\n";
      
  } else /* When the size is symbolic */
  {
    
    //llvm::outs() << " FOUND MALLOC WITH SYMBOLIC SIZE\n";
    
    uint64_t lower_bound = INT_MAX;
    //llvm::outs() << "Executor::executeAlloc(): Received an alloc request with symbolic size.\n";

    // See if a *really* big value is possible. If so assume
    // malloc will fail for it, so lets fork and return 0.
    StatePair hugeSize = 
      fork(state, 
           UltExpr::create(size, ConstantExpr::alloc(1<<30, size->getWidth())), 
           true);
    
    // JV: Add edges for states
    this->trackEdges(state, hugeSize, EDGE_HEAP, "ahs");
    
    if (hugeSize.second) {
      klee_warning("Found huge malloc, forking and returning 0 for the second state.\n");
      bindLocal(target, *hugeSize.second, 
                ConstantExpr::alloc(0, Context::get().getPointerWidth()));
      /* We are done with hugeSize.second */
    }

    //llvm::outs() << "Executor::executeAlloc(): hugeSize.first = " << hugeSize.first << "\n";
    if (!hugeSize.first) // Symbolic size can only be huge
      {
	klee_warning("Found klee state where symbolic size can only be huge, suspicious (should never happen)\n");
	return;
      }
    assert(hugeSize.first);
    assert(hugeSize.first == &state);

    /* IVANP: We could have used 'getRange()' as below but it seems slower then
     * our custom binary search <getLowerBound()>*/
    bool timedout;
    solver->setTimeout(coreSolverTimeout);
    std::pair< ref<Expr>, ref<Expr> > range = solver->getRange(state, size, timedout);
    if (ConstantExpr *lowerbound_const_exp = dyn_cast<ConstantExpr>(range.first)) 
      lower_bound = lowerbound_const_exp->getZExtValue();
    solver->setTimeout(0);
    
    //lower_bound = getLowerBound(state, size); // Find minumum value of size which satisfies state.constraints
    (*debugHeapFile) << "Executor::executeAlloc(): Received an alloc request with symbolic size. The minimum size is " << lower_bound << "\n";
    mo = memory->allocateWithSymbolicSize(size, lower_bound, isLocal, false, state.prevPC->inst);
    mo->guest_address_set(state.addressSpace.getFreeMemchunkAtGuest());
    //llvm::outs() << "Executor::executeAlloc(): allocated at address: " << mo->guest_address() << "; size: " << mo->size << "\n";
  }

  {
    if (!mo) {
      bindLocal(target, state, 
                ConstantExpr::alloc(0, Context::get().getPointerWidth()));
    } else {
      //llvm::outs() << "Executor::executeAlloc(): Binding new object into state\n";
      ObjectState *os = bindObjectInState(state, mo, isLocal);
      if (zeroMemory) {
        os->initializeToZero();
      } else {
        os->initializeToRandom();
      }
      bindLocal(target, state, mo->getBaseExpr());
      
      if (reallocFrom) {
        unsigned count = std::min(reallocFrom->size, os->size);
        for (unsigned i=0; i<count; i++)
          os->write(i, reallocFrom->read8(i));
        state.addressSpace.unbindObject(reallocFrom->getObject());
	if(!target) /* If we realloc a dynamic object */
	{
	  mo->guest_address_set(reallocFrom->getObject()->guest_address());
	  mo->allocSite = reallocFrom->getObject()->allocSite;
          //llvm::outs() << "Executor::executeAlloc(): relocated to: " << mo->guest_address() << "; size: " << mo->size << "\n";
	}
      }
    }
  }
}

void Executor::executeFree(ExecutionState &state,
                           ref<Expr> address,
                           KInstruction *target) {
  StatePair zeroPointer = fork(state, Expr::createIsZero(address), true);

  // JV: Add edges for states
  this->trackEdges(state, zeroPointer, EDGE_HEAP, "zfp");
  
  if (zeroPointer.first) {
    if (target)
      bindLocal(target, *zeroPointer.first, Expr::createPointer(0));
  }
  if (zeroPointer.second) { // address != 0
    ExactResolutionList rl;
    resolveExact(*zeroPointer.second, address, rl, "free");
    
    for (Executor::ExactResolutionList::iterator it = rl.begin(), 
           ie = rl.end(); it != ie; ++it) {
      const MemoryObject *mo = it->first.first;
      if (mo->isLocal) {
	doDumpViolationState(state, "free of alloca");
        terminateStateOnError(*it->second, "free of alloca", Free, NULL,
                              getAddressInfo(*it->second, address));
      } else if (mo->isGlobal) {
	doDumpViolationState(state, "free of global");
        terminateStateOnError(*it->second, "free of global", Free, NULL,
                              getAddressInfo(*it->second, address));
      } else {
        it->second->addressSpace.unbindObject(mo);
        if (target)
          bindLocal(target, *it->second, Expr::createPointer(0));
      }
    }
  }
}

void Executor::resolveExact(ExecutionState &state,
                            ref<Expr> p,
                            ExactResolutionList &results, 
                            const std::string &name) {
  // XXX we may want to be capping this?
  ResolutionList rl;
  state.addressSpace.resolve(state, solver, p, rl);
  
  ExecutionState *unbound = &state;
  for (ResolutionList::iterator it = rl.begin(), ie = rl.end(); 
       it != ie; ++it) {
    ref<Expr> inBounds = EqExpr::create(p, it->first->getBaseExpr());
    
    StatePair branches = fork(*unbound, inBounds, true);

    // JV: Add edges for states
    this->trackEdges(*unbound, branches, EDGE_HEAP, "rslvxct");
    
    if (branches.first)
      results.push_back(std::make_pair(*it, branches.first));

    unbound = branches.second;
    if (!unbound) // Fork failure
      break;
  }

  if (unbound) {

    doDumpViolationState(state, "Invalid pointer access: " + name);
    
    terminateStateOnError(*unbound, "memory error: invalid pointer: " + name,
                          Ptr, NULL, getAddressInfo(*unbound, p));
  }
}

/* \brief Find the base of the object for Store instruction
 * TODO: 1. Add better description
 *       2. Improve readability
 *       3. Add alloca cache 
*/
ref<Expr> Executor::getDestArgForInstruction(ExecutionState &state, KInstruction *ki)
{
    StoreInst* SI = dyn_cast<StoreInst>(ki->inst);
    LoadInst* LI = dyn_cast<LoadInst>(ki->inst);
    assert(SI || LI);
    /* For Store instruction, the dest index is 1, for load it's 0 */
    unsigned int dest_idx = (SI ? 1 : 0);
    //llvm::outs() << "Executor::getDestArgForInstruction():Store: " << *(ki->inst) << "\n";
    if (Instruction *gep = dyn_cast<Instruction>(ki->inst->getOperand(dest_idx)))
    {
      if (gep->getOpcode() == Instruction::GetElementPtr)
      {
        if(state.getElmntPtrBases.count(gep))
        {
          //llvm::outs() << "Executor::getDestArgForInstruction(): found cached getElementPtr, base = "
          //             <<  state.getElmntPtrBases[gep] << "\n";
          return state.getElmntPtrBases[gep];
        }
      } 
      if (gep->getOpcode() == Instruction::Alloca)
      {
        //llvm::outs() << "  Executor::getDestArgForInstruction(): cache for allocas not implemented yet: alloc instr: " << *gep << "\n";
      }
      else
      {
        //llvm::outs() << "                                other instr: " << *gep << "\n";
      }
    }
    else if (llvm::ConstantExpr *CE = dyn_cast<llvm::ConstantExpr>(ki->inst->getOperand(dest_idx)))
    {
      if (CE->getOpcode() == Instruction::GetElementPtr)
      {
        assert(CE->isGEPWithNoNotionalOverIndexing());
        //llvm::outs() << "                                      constant gep = \n";// <<  << "\n";
        //CE->print(outs());
        if (llvm::ConstantInt *CE1 = dyn_cast<llvm::ConstantInt>(CE->getOperand(0)))
        {
          llvm::outs() << "\n                                      base value = " << CE1->getZExtValue() << "\n";
          return ConstantExpr::create(CE1->getZExtValue(), Context::get().getPointerWidth());
        }
        //else if(llvm::GlobalVariable *GV = dyn_cast<llvm::GlobalVariable>(CE->getOperand(0)))
        else if(llvm::GlobalValue *GV = dyn_cast<llvm::GlobalValue>(CE->getOperand(0)))
        {
          assert(globalObjects.count(GV));
          const MemoryObject *mo = globalObjects[GV];
          //objects.find(mo);
          const MemoryMap::value_type *res = state.addressSpace.objects.lookup_previous(mo);
          assert(res);
          ObjectPair op = *res;
          const ObjectState *os = op.second;
          ref<Expr> value_of_global = os->read(0, Context::get().getPointerWidth());
          //llvm::outs() << "\n                                      base value of GEP is a global, value = " << value_of_global << "\n";
          //llvm::outs() << "\n                                                                     address = " << globalAddresses[GV] << "\n";
          return globalAddresses[GV];
        }
        else
          assert(0 && "The base for constant GEP is not a constant or global variable; seems that Ivan doesnt's really know llvm...");
        llvm::outs() << "\n";
      }
      //else if (llvm::Constant *CE = dyn_cast<llvm::Constant>(SI->getOperand(1)))
      else if (llvm::ConstantInt *CE1 = dyn_cast<llvm::ConstantInt>(CE))
      {
          //llvm::outs() << "                                      constant gep\n";// <<  << "\n";
          return ConstantExpr::create(CE1->getZExtValue(), Context::get().getPointerWidth());
      }
    }
    else
    {
        //llvm::outs() << "                                      unknown gep\n";// <<  << "\n";
        //ki->inst->getOperand(dest_idx)->print(outs());
        //llvm::outs() << "\n";
    }
    return ConstantExpr::create(0, Context::get().getPointerWidth());
}

/* \brief Extract the base of destination object for Store or Load instruction
 *
 * \description The destination operand for a Store/Load instruction is often
 *              getElementPtr instruction, Alloca instruction, or a
 *              Constant. For all these cases we can extract the base
 *              address of the corresponding object. Note that during
 *              execution we record all GetElementPtr and Alloca
 *              instructions.
 * 
 * \param ki The Store/Load instruction for which we try to find the dest
 *           memory object.
 * \return The destination memory object for the Store/Load instruction, or
 *         NULL if could not find.
 * \TODO: add support for symboolic addresses
*/
//bool Executor::resolveDynammicObject(ExecutionState &state, KInstruction *ki, ObjectPair &op)
bool Executor::resolveFromInstruction(ExecutionState &state, KInstruction *ki, ObjectPair &op)
{
  if(!ki)
    return false;
  ref<Expr> addressExpr = getDestArgForInstruction(state, ki);
  ConstantExpr *tmp = dyn_cast<ConstantExpr>(addressExpr);
  if(!tmp)
    {
      klee_warning("resolveFromInstruction: Symbolic address case (unsupported) \n");
      return false; /* We don't support symbolic addresses here yet */
    }
  uint64_t address = tmp->getZExtValue();
  if(address == 0)
    return false;
  bool success = state.addressSpace.resolveOne(tmp, op);
  if(!success)
    return false;
  //const MemoryObject *mo = op.first;
  return true;
  //if(mo->isSizeDynamic)
  //  return true;
  //return false;
}

/* \brief Resize all objects with dynamic size according the state's
 *        constraints.
 * 
 * \param state Consider address space of this state
 * \return void
*/


// JV: THIS IS NOT USED ANMORE IN CURRENT -HEAD (4/14/17) 
void Executor::resizeAllDynamicObjects(ExecutionState &state)
{
  //llvm::outs() << "Executor::resizeAllDynamicObjects(): inside\n";
  MemoryMap::iterator op_begin = state.addressSpace.objects.begin();
  MemoryMap::iterator op_end = state.addressSpace.objects.end();

  const MemoryObject *mo = NULL;
  const ObjectState *os = NULL;
  --op_end; // Going from the end
  while (op_begin != op_end)
  {
    mo = op_end->first;
    os = op_end->second;
    //llvm::outs() << "Executor::resizeAllDynamicObjects(): considering object at address: " << mo->guest_address() << "\n";
    if(!(mo->isSizeDynamic))
    {
      //llvm::outs() << "Executor::resizeAllDynamicObjects(): it's not dynamic\n";
      break; /* All dynamic objects are grouped at high addresses */
    }
    else
    {
      //llvm::outs() << "Executor::resizeAllDynamicObjects(): it's dynamic, resizing\n";
      /* We set the target insturction below to NULL because:
         our dynamic object was already mapped to the original
         malloc (i.e. where it was first allocated) */ 
      executeAlloc(state, mo->symbolic_size, false, 0, false, os);
    }
    --op_end; // Going from the end
  }
}

/* \brief Resize object with dynamic size according the state's
 *        constraints.
 * 
 * \param state Consider memory object from this state
 * \return void
*/
ObjectState* Executor::resizeDynamicObject(ExecutionState &state, ObjectPair &old_op)
{
  const MemoryObject *old_mo = old_op.first;
  const ObjectState *old_os = old_op.second;
  bool isLocal = false;
  bool timedout = false;
  
  /* Find the lower bound for the object's symolic size */
  uint64_t lower_bound = INT_MAX;
  solver->setTimeout(coreSolverTimeout);
  std::pair< ref<Expr>, ref<Expr> > range = solver->getRange(state,
							     old_mo->symbolic_size,
							     timedout);
  if (ConstantExpr *lowerbound_const_exp = dyn_cast<ConstantExpr>(range.first)) 
    lower_bound = lowerbound_const_exp->getZExtValue();
  solver->setTimeout(0);
  
  llvm::outs() << "Executor::resizeDynamicObject(): Received a resize request. The minimum size is " << lower_bound << "\n";
  MemoryObject *new_mo = memory->allocateWithSymbolicSize(old_mo->symbolic_size, lower_bound, isLocal, false, state.prevPC->inst);
  assert(new_mo && "Resizing of dynamic object failed (due to failed malloc)");

  ObjectState *new_os = bindObjectInState(state, new_mo, isLocal);
  new_os->initializeToZero();
  //new_os->initializeToRandom();
  unsigned count = std::min(old_os->size, new_os->size);
  for (unsigned i=0; i<count; i++)
    new_os->write(i, old_os->read8(i));
  new_mo->guest_address_set(old_mo->guest_address());
  new_mo->allocSite = old_mo->allocSite;

  state.addressSpace.unbindObject(old_mo);
  return new_os;
}

void Executor::executeMemoryOperation(ExecutionState &state,
                                      bool isWrite,
                                      ref<Expr> address,
                                      ref<Expr> value /* undef if read */,
                                      KInstruction *target /* undef if write */,
				      bool checkDynamicObjects) {
  Expr::Width type = (isWrite ? value->getWidth() : 
                     getWidthForLLVMType(target->inst->getType()));
  unsigned bytes = Expr::getMinBytesForWidth(type);

  if (SimplifySymIndices) {
    if (!isa<ConstantExpr>(address))
      address = state.constraints.simplifyExpr(address);
    if (isWrite && !isa<ConstantExpr>(value))
      value = state.constraints.simplifyExpr(value);
  }

  ObjectPair op;
  bool resolved;
  bool success;
  resolved = resolveFromInstruction(state, target, op);
  //if(resolved)
  //  llvm::outs() << "--> resolved from cache\n";
  if(!resolved)
  {
    // llvm::outs() << "Executor::executeMemoryOperation(): Could not resolve
    // object from case, wil back off to resolve()\n";
    ResolutionList rl;  
    solver->setTimeout(coreSolverTimeout);
    //bool incomplete = state.addressSpace.resolve(state, solver, address,
    //                                             rl, 0, coreSolverTimeout);
    //state.addressSpace.resolve(state, solver, address, rl, 0, coreSolverTimeout);
    state.addressSpace.resolveOne(state, solver, address, op, success);
    solver->setTimeout(0);
    //if(rl.size() != 1)
    if(!success)
    {

      doDumpViolationState(state, "OOB pointer resolveOne");
      
      //llvm::outs() << "Executor::executeMemoryOperation(): rl.size = "
      //             << rl.size() << ". It's a memory error\n";
      llvm::errs() << "HKLEE: Executor::executeMemoryOperation(): Could not resolve a pointer "
		       << "(at address " << address << "). It's a memory error\n";
      terminateStateOnError(state, "memory error: out of bound pointer", Ptr,
                            NULL, getAddressInfo(state, address));
      return;
    }

    //op = rl[0];
  }

  const MemoryObject *mo = op.first;

  if (MaxSymArraySize && mo->size>=MaxSymArraySize) {
    address = toConstant(state, address, "max-sym-array-size");
  }
  
  ref<Expr> offset = mo->getOffsetExpr(address);

  bool inBounds;
  solver->setTimeout(coreSolverTimeout);
  success = solver->mustBeTrue(state, 
			       mo->getBoundsCheckOffset(offset, bytes),
			       inBounds);
  solver->setTimeout(0);
  if (!success) {
    state.pc = state.prevPC;
    terminateStateEarly(state, "Query timed out (bounds check).");
    return;
  }

  if (inBounds) {
    const ObjectState *os;
    if(mo->isSizeDynamic)
    {
      // It seems like we dont destroy the previous object here
      os = resizeDynamicObject(state, op);
      mo = os->getObject();
    } else
      os = op.second;
    //const ObjectState *os = op.second;
    if (isWrite) {
      if (os->readOnly) {
        terminateStateOnError(state, "memory error: object read only",
                              ReadOnly);
      } else {
        ObjectState *wos = state.addressSpace.getWriteable(mo, os);
        wos->write(offset, value);
      }          
    } else {
      ref<Expr> result = os->read(offset, type);

      // JV: why is KLEE providing this option?
      if (interpreterOpts.MakeConcreteSymbolic)
        result = replaceReadWithSymbolic(state, result);
      
      bindLocal(target, state, result);
    }

    return;
  }

  (*debugHeapFile) << "Executor::executeMemoryOperation(): Resolved pointer of " << (mo->isSizeDynamic ? "DYNAMIC" : "STATIC") << " size WIH OOB ACCESS\n";

  std::string label = "";
  label += (mo->isLocal ? "Local" : (mo->isGlobal ? "Global" : (mo->isFixed ? "Fixed" : "Unk")));
  label += " OOB";
  doDumpViolationState(state, label);

  std::string straddr = getAddressInfo(state, address);
  
  terminateStateOnError(state, "memory error: out of bound pointer", Ptr, NULL, straddr);
  return;
}

void Executor::executeMakeSymbolic(ExecutionState &state, 
                                   const MemoryObject *mo,
                                   const std::string &name) {
  // Create a new object state for the memory object (instead of a copy).
  if (!replayKTest) {
    // Find a unique name for this array.  First try the original name,
    // or if that fails try adding a unique identifier.
    unsigned id = 0;
    std::string uniqueName = name;
    while (!state.arrayNames.insert(uniqueName).second) {
      uniqueName = name + "_" + llvm::utostr(++id);
    }
    const Array *array = arrayCache.CreateArray(uniqueName, mo->size);
    bindObjectInState(state, mo, false, array);
    state.addSymbolic(mo, array);
    
    std::map< ExecutionState*, std::vector<SeedInfo> >::iterator it = 
      seedMap.find(&state);
    if (it!=seedMap.end()) { // In seed mode we need to add this as a
                             // binding.
      for (std::vector<SeedInfo>::iterator siit = it->second.begin(), 
             siie = it->second.end(); siit != siie; ++siit) {
        SeedInfo &si = *siit;
        KTestObject *obj = si.getNextInput(mo, NamedSeedMatching);

        if (!obj) {
          if (ZeroSeedExtension) {
            std::vector<unsigned char> &values = si.assignment.bindings[array];
            values = std::vector<unsigned char>(mo->size, '\0');
          } else if (!AllowSeedExtension) {
            terminateStateOnError(state, "ran out of inputs during seeding",
                                  User);
            break;
          }
        } else {
          if (obj->numBytes != mo->size &&
              ((!(AllowSeedExtension || ZeroSeedExtension)
                && obj->numBytes < mo->size) ||
               (!AllowSeedTruncation && obj->numBytes > mo->size))) {
	    std::stringstream msg;
	    msg << "replace size mismatch: "
		<< mo->name << "[" << mo->size << "]"
		<< " vs " << obj->name << "[" << obj->numBytes << "]"
		<< " in test\n";

            terminateStateOnError(state, msg.str(), User);
            break;
          } else {
            std::vector<unsigned char> &values = si.assignment.bindings[array];
            values.insert(values.begin(), obj->bytes, 
                          obj->bytes + std::min(obj->numBytes, mo->size));
            if (ZeroSeedExtension) {
              for (unsigned i=obj->numBytes; i<mo->size; ++i)
                values.push_back('\0');
            }
          }
        }
      }
    }
  } else {
    ObjectState *os = bindObjectInState(state, mo, false);
    if (replayPosition >= replayKTest->numObjects) {
      terminateStateOnError(state, "replay count mismatch", User);
    } else {
      KTestObject *obj = &replayKTest->objects[replayPosition++];
      if (obj->numBytes != mo->size) {
        terminateStateOnError(state, "replay size mismatch", User);
      } else {
        for (unsigned i=0; i<mo->size; i++)
          os->write8(i, obj->bytes[i]);
      }
    }
  }
}

/***/

void Executor::runFunctionAsMain(Function *f,
				 int argc,
				 char **argv,
				 char **envp) {
  std::vector<ref<Expr> > arguments;

  // force deterministic initialization of memory objects
  srand(1);
  srandom(1);
  
  MemoryObject *argvMO = 0;

  // In order to make uclibc happy and be closer to what the system is
  // doing we lay out the environments at the end of the argv array
  // (both are terminated by a null). There is also a final terminating
  // null that uclibc seems to expect, possibly the ELF header?

  int envc;
  for (envc=0; envp[envc]; ++envc) ;

  unsigned NumPtrBytes = Context::get().getPointerWidth() / 8;
  KFunction *kf = kmodule->functionMap[f];
  assert(kf);
  Function::arg_iterator ai = f->arg_begin(), ae = f->arg_end();
  if (ai!=ae) {
    arguments.push_back(ConstantExpr::alloc(argc, Expr::Int32));
    if (++ai!=ae) {
      Instruction *first = static_cast<Instruction *>(f->begin()->begin());
      argvMO =
          memory->allocate((argc + 1 + envc + 1 + 1) * NumPtrBytes,
                           /*isLocal=*/false, /*isGlobal=*/true,
                           /*allocSite=*/first, /*alignment=*/8);

      if (!argvMO)
        klee_error("Could not allocate memory for function arguments");

      arguments.push_back(argvMO->getBaseExpr());

      if (++ai!=ae) {
        uint64_t envp_start = argvMO->guest_address() + (argc+1)*NumPtrBytes;
        arguments.push_back(Expr::createPointer(envp_start));

        if (++ai!=ae)
          klee_error("invalid main function (expect 0-3 arguments)");
      }
    }
  }

  ExecutionState *state = new ExecutionState(kmodule->functionMap[f]);

  // JV: Add state id
  if (state)
    state->id = this->next_state_id++;
  
  if (pathWriter) 
    state->pathOS = pathWriter->open();
  if (symPathWriter) 
    state->symPathOS = symPathWriter->open();


  if (statsTracker)
    statsTracker->framePushed(*state, 0);

  assert(arguments.size() == f->arg_size() && "wrong number of arguments");
  for (unsigned i = 0, e = f->arg_size(); i != e; ++i)
    bindArgument(kf, i, *state, arguments[i]);

  if (argvMO) {
    ObjectState *argvOS = bindObjectInState(*state, argvMO, false);

    for (int i=0; i<argc+1+envc+1+1; i++) {
      if (i==argc || i>=argc+1+envc) {
        // Write NULL pointer
        argvOS->write(i * NumPtrBytes, Expr::createPointer(0));
      } else {
        char *s = i<argc ? argv[i] : envp[i-(argc+1)];
        int j, len = strlen(s);

        MemoryObject *arg =
            memory->allocate(len + 1, /*isLocal=*/false, /*isGlobal=*/true,
                             /*allocSite=*/state->pc->inst, /*alignment=*/8);
        if (!arg)
          klee_error("Could not allocate memory for function arguments");
        ObjectState *os = bindObjectInState(*state, arg, false);
        for (j=0; j<len+1; j++)
          os->write8(j, s[j]);

        // Write pointer to newly allocated and initialised argv/envp c-string
        argvOS->write(i * NumPtrBytes, arg->getBaseExpr());
      }
    }
  }
  
  initializeGlobals(*state);

  processTree = new PTree(state);
  state->ptreeNode = processTree->root;
  run(*state);
  delete processTree;
  processTree = 0;

  // hack to clear memory objects
  delete memory;
  memory = new MemoryManager(NULL);

  globalObjects.clear();
  globalAddresses.clear();

  if (statsTracker)
    statsTracker->done();
}

unsigned Executor::getPathStreamID(const ExecutionState &state) {
  assert(pathWriter);
  return state.pathOS.getID();
}

unsigned Executor::getSymbolicPathStreamID(const ExecutionState &state) {
  assert(symPathWriter);
  return state.symPathOS.getID();
}

void Executor::getConstraintLog(const ExecutionState &state, std::string &res,
                                Interpreter::LogType logFormat) {

  std::ostringstream info;

  switch (logFormat) {
  case STP: {
    Query query(state.constraints, ConstantExpr::alloc(0, Expr::Bool));
    char *log = solver->getConstraintLog(query);
    res = std::string(log);
    free(log);
  } break;

  case KQUERY: {
    std::string Str;
    llvm::raw_string_ostream info(Str);
    ExprPPrinter::printConstraints(info, state.constraints);
    res = info.str();
  } break;

  case SMTLIB2: {
    std::string Str;
    llvm::raw_string_ostream info(Str);
    ExprSMTLIBPrinter printer;
    printer.setOutput(info);
    Query query(state.constraints, ConstantExpr::alloc(0, Expr::Bool));
    printer.setQuery(query);
    printer.generateOutput();
    res = info.str();
  } break;

  default:
    klee_warning("Executor::getConstraintLog() : Log format not supported!");
  }
}

bool Executor::getSymbolicSolution(const ExecutionState &state,
                                   std::vector< 
                                   std::pair<std::string,
                                   std::vector<unsigned char> > >
                                   &res) {
  solver->setTimeout(coreSolverTimeout);

  ExecutionState tmp(state);

  // Go through each byte in every test case and attempt to restrict
  // it to the constraints contained in cexPreferences.  (Note:
  // usually this means trying to make it an ASCII character (0-127)
  // and therefore human readable. It is also possible to customize
  // the preferred constraints.  See test/Features/PreferCex.c for
  // an example) While this process can be very expensive, it can
  // also make understanding individual test cases much easier.
  for (unsigned i = 0; i != state.symbolics.size(); ++i) {
    const MemoryObject *mo = state.symbolics[i].first;
    std::vector< ref<Expr> >::const_iterator pi = 
      mo->cexPreferences.begin(), pie = mo->cexPreferences.end();
    for (; pi != pie; ++pi) {
      bool mustBeTrue;
      // Attempt to bound byte to constraints held in cexPreferences
      bool success = solver->mustBeTrue(tmp, Expr::createIsZero(*pi), 
					mustBeTrue);
      // If it isn't possible to constrain this particular byte in the desired
      // way (normally this would mean that the byte can't be constrained to
      // be between 0 and 127 without making the entire constraint list UNSAT)
      // then just continue on to the next byte.
      if (!success) break;
      // If the particular constraint operated on in this iteration through
      // the loop isn't implied then add it to the list of constraints.
      if (!mustBeTrue) tmp.addConstraint(*pi);
    }
    if (pi!=pie) break;
  }

  std::vector< std::vector<unsigned char> > values;
  std::vector<const Array*> objects;
  for (unsigned i = 0; i != state.symbolics.size(); ++i)
    objects.push_back(state.symbolics[i].second);
  bool success = solver->getInitialValues(tmp, objects, values);
  solver->setTimeout(0);
  if (!success) {
    klee_warning("unable to compute initial values (invalid constraints?)!");
    ExprPPrinter::printQuery(llvm::errs(), state.constraints,
                             ConstantExpr::alloc(0, Expr::Bool));
    return false;
  }
  
  for (unsigned i = 0; i != state.symbolics.size(); ++i)
    res.push_back(std::make_pair(state.symbolics[i].first->name, values[i]));
  return true;
}

void Executor::getCoveredLines(const ExecutionState &state,
                               std::map<const std::string*, std::set<unsigned> > &res) {
  res = state.coveredLines;
}

void Executor::doImpliedValueConcretization(ExecutionState &state,
                                            ref<Expr> e,
                                            ref<ConstantExpr> value) {
  abort(); // FIXME: Broken until we sort out how to do the write back.

  if (DebugCheckForImpliedValues)
    ImpliedValue::checkForImpliedValues(solver->solver, e, value);

  ImpliedValueList results;
  ImpliedValue::getImpliedValues(e, value, results);
  for (ImpliedValueList::iterator it = results.begin(), ie = results.end();
       it != ie; ++it) {
    ReadExpr *re = it->first.get();
    
    if (ConstantExpr *CE = dyn_cast<ConstantExpr>(re->index)) {
      // FIXME: This is the sole remaining usage of the Array object
      // variable. Kill me.
      const MemoryObject *mo = 0; //re->updates.root->object;
      const ObjectState *os = state.addressSpace.findObject(mo);

      if (!os) {
        // object has been free'd, no need to concretize (although as
        // in other cases we would like to concretize the outstanding
        // reads, but we have no facility for that yet)
      } else {
        assert(!os->readOnly && 
               "not possible? read only object with static read?");
        ObjectState *wos = state.addressSpace.getWriteable(mo, os);
        wos->write(CE, it->second);
      }
    }
  }
}

Expr::Width Executor::getWidthForLLVMType(LLVM_TYPE_Q llvm::Type *type) const {
  return kmodule->targetData->getTypeSizeInBits(type);
}

size_t Executor::getAllocationAlignment(const llvm::Value *allocSite) const {
  // FIXME: 8 was the previous default. We shouldn't hard code this
  // and should fetch the default from elsewhere.
  const size_t forcedAlignment = 8;
  size_t alignment = 0;
  LLVM_TYPE_Q llvm::Type *type = NULL;
  std::string allocationSiteName(allocSite->getName().str());
  if (const GlobalValue *GV = dyn_cast<GlobalValue>(allocSite)) {
    alignment = GV->getAlignment();
    if (const GlobalVariable *globalVar = dyn_cast<GlobalVariable>(GV)) {
      // All GlobalVariables's have pointer type
      LLVM_TYPE_Q llvm::PointerType *ptrType =
          dyn_cast<llvm::PointerType>(globalVar->getType());
      assert(ptrType && "globalVar's type is not a pointer");
      type = ptrType->getElementType();
    } else {
      type = GV->getType();
    }
  } else if (const AllocaInst *AI = dyn_cast<AllocaInst>(allocSite)) {
    alignment = AI->getAlignment();
    type = AI->getAllocatedType();
  } else if (isa<InvokeInst>(allocSite) || isa<CallInst>(allocSite)) {
    // FIXME: Model the semantics of the call to use the right alignment
    llvm::Value *allocSiteNonConst = const_cast<llvm::Value *>(allocSite);
    const CallSite cs = (isa<InvokeInst>(allocSiteNonConst)
                             ? CallSite(cast<InvokeInst>(allocSiteNonConst))
                             : CallSite(cast<CallInst>(allocSiteNonConst)));
    llvm::Function *fn =
        klee::getDirectCallTarget(cs, /*moduleIsFullyLinked=*/true);
    if (fn)
      allocationSiteName = fn->getName().str();

    klee_warning_once(fn != NULL ? fn : allocSite,
                      "Alignment of memory from call \"%s\" is not "
                      "modelled. Using alignment of %zu.",
                      allocationSiteName.c_str(), forcedAlignment);
    alignment = forcedAlignment;
  } else {
    llvm_unreachable("Unhandled allocation site");
  }

  if (alignment == 0) {
    assert(type != NULL);
    // No specified alignment. Get the alignment for the type.
    if (type->isSized()) {
      alignment = kmodule->targetData->getPrefTypeAlignment(type);
    } else {
      klee_warning_once(allocSite, "Cannot determine memory alignment for "
                                   "\"%s\". Using alignment of %zu.",
                        allocationSiteName.c_str(), forcedAlignment);
      alignment = forcedAlignment;
    }
  }

  // Currently we require alignment be a power of 2
  if (!bits64::isPowerOfTwo(alignment)) {
    klee_warning_once(allocSite, "Alignment of %zu requested for %s but this "
                                 "not supported. Using alignment of %zu",
                      alignment, allocSite->getName().str().c_str(),
                      forcedAlignment);
    alignment = forcedAlignment;
  }
  assert(bits64::isPowerOfTwo(alignment) &&
         "Returned alignment must be a power of two");
  return alignment;
}

void Executor::prepareForEarlyExit() {
  if (statsTracker) {
    // Make sure stats get flushed out
    statsTracker->done();
  }
}
///

Interpreter *Interpreter::create(LLVMContext &ctx, const InterpreterOptions &opts,
                                 InterpreterHandler *ih) {
  return new Executor(ctx, opts, ih);
}
