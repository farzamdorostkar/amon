//===-- AddressMonitor.cpp ------------------------------------------------===//
//
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file is a part of AddressMonitor.
//
// AMon is a dynamic tool designed to detect temporal and spatial memory access 
// violations in C programs at runtime.
//
// The tool is under development.
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/Instrumentation/AddressMonitor.h"
#include "llvm/IR/InlineAsm.h"

#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/SmallString.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringExtras.h"
#include "llvm/Analysis/CaptureTracking.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/ValueTracking.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Intrinsics.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Metadata.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/ProfileData/InstrProf.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/Debug.h"
#include "llvm/Support/MathExtras.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Instrumentation.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/EscapeEnumerator.h"
#include "llvm/Transforms/Utils/Local.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"

using namespace llvm;

// Command-line options.

static cl::opt<bool> ClInstrumentReads(
  "amon_instrument_reads",
  cl::desc("Instrument read instructions"),
  cl::Hidden,
  cl::init(true));

static cl::opt<bool> ClInstrumentWrites(
  "amon_instrument_writes",
  cl::desc("Instrument write instructions"),
  cl::Hidden,
  cl::init(true));

static cl::opt<bool> ClInterceptAlloca(
  "amon_intercept_alloca",
  cl::desc("Intercept stack allocation (alloca)"),
  cl::Hidden,
  cl::init(false));

#define DEBUG_TYPE "amon"

namespace {

class ToUntaint {
public:
  Use *PtrOperandUse;
  Type *AccessType;
  unsigned index;
  bool Instrument;

  ToUntaint(Instruction *I, unsigned idx, bool istrmnt = true) {
    PtrOperandUse = &I->getOperandUse(idx);
    AccessType = I->getAccessType();
    index = idx;
    Instrument = istrmnt;
  }

  Instruction *getInsn() { return cast<Instruction>(PtrOperandUse->getUser()); }

  Value *getPtr() { return PtrOperandUse->get(); }

  Type *getAccessType() { return AccessType; }

  bool toInstrument() { return Instrument; }

  void setInstrument(bool istrmnt) { Instrument = istrmnt; }
};

// AddressMonitor
//
// Instantiating AddressMonitor

struct AddressMonitor {
  AddressMonitor() {}

  //bool sanitizeFunction(Function &F, const TargetLibraryInfo &TLI);
  bool monitorFunction(Function &F, const TargetLibraryInfo &TLI);
  void checkInst(Instruction *I, SmallVectorImpl<ToUntaint> &OperandsToUntaint);
  void untaint(ToUntaint &It, const DataLayout &DL);

private:
  // Internal Instruction wrapper that contains more information about the
  // Instruction from prior analysis.
  struct InstructionInfo {
    // Instrumentation emitted for this instruction is for a compounded set of
    // read and write operations in the same basic block.
    static constexpr unsigned kCompoundRW = (1U << 0);

    explicit InstructionInfo(Instruction *Inst) : Inst(Inst) {}

    Instruction *Inst;
    unsigned Flags = 0;
  };

  void initialize(Module &M);
  bool taint(Instruction *II, const DataLayout &DL);

  Type *IntptrTy;

  // Used to instrument write operations.
  FunctionCallee AMonWrite;

  // Used to instrument read operations.
  FunctionCallee AMonRead;
};

}  // namespace

PreservedAnalyses AddressMonitorPass::run(Function &F,
                                           FunctionAnalysisManager &FAM) {
  AddressMonitor AMon;
  if (AMon.monitorFunction(F, FAM.getResult<TargetLibraryAnalysis>(F)))
    return PreservedAnalyses::none();
  return PreservedAnalyses::all();
}

PreservedAnalyses ModuleAddressMonitorPass::run(Module &M,
                                                 ModuleAnalysisManager &MAM) {
  return PreservedAnalyses::none();
}

void AddressMonitor::initialize(Module &M) {
  const DataLayout &DL = M.getDataLayout();
  IntptrTy = DL.getIntPtrType(M.getContext());

  IRBuilder<> IRB(M.getContext());
  AttributeList Attr;
  Attr = Attr.addFnAttribute(M.getContext(), Attribute::NoUnwind);

  AMonWrite = M.getOrInsertFunction("amon_write", Attr, IRB.getVoidTy(), IRB.getInt8PtrTy(), IRB.getInt64Ty());

  AMonRead = M.getOrInsertFunction("amon_read", Attr, IRB.getVoidTy(), IRB.getInt8PtrTy(), IRB.getInt64Ty());
}

// 1. Generate the untainted version of the pointer operand
// 2. Replace the tainted pointer operand with its untainted version.
// 3. Instrument the access to enable runtime verification.

void AddressMonitor::untaint(ToUntaint &toUntaint, const DataLayout &DL) {
  Instruction *I = toUntaint.getInsn();
  Value *Ptr = toUntaint.getPtr();

  PointerType *PtrTy = cast<PointerType>(Ptr->getType());
  LLVMContext &Ctx = I->getContext();
  IntegerType *IntTy = DL.getIntPtrType(Ctx, PtrTy->getAddressSpace());

  // Define the untainting mask: 0x0000FFFFFFFFFFFF
  Value *UntaintMask = ConstantInt::get(IntTy, 0x0000FFFFFFFFFFFFLL);

  InstrumentationIRBuilder IRB(I);

  // Use llvm.ptrmask intrinsic to generate the untainted pointer.
  Value *UntaintedPtr = IRB.CreateIntrinsic(Intrinsic::ptrmask, {PtrTy, IntTy}, {Ptr, UntaintMask});

  // In the instruction, replace the tainted pointer operand with its untainted version.
  I->setOperand(toUntaint.index, UntaintedPtr);

    // Perform instrumentation.
  if (toUntaint.toInstrument()) {
    bool isWrite;

    // Determine the type of the accessed value
    Type *AccessType = nullptr;

    if (auto *SI = dyn_cast<StoreInst>(I)) {
      AccessType = SI->getValueOperand()->getType();
      isWrite = true;
    }
    else if (auto *LI = dyn_cast<LoadInst>(I)) {
      AccessType = LI->getType();
      isWrite = false;
    }

    if (AccessType) {
      // Extract the size of the accessed memory from the type of the value being accessed.
      // Use the DataLayout to find the size of the type being stored.
      uint64_t AccessSize = DL.getTypeStoreSize(AccessType);

      Value *SizeVal = ConstantInt::get(Type::getInt64Ty(Ctx), AccessSize);

      IRB.CreateCall(isWrite ? AMonWrite : AMonRead, {Ptr, SizeVal});
    }
  }
}

void AddressMonitor::checkInst(Instruction *I,
                              SmallVectorImpl<ToUntaint> &OperandsToUntaint) {
  if (LoadInst *LI = dyn_cast<LoadInst>(I)) {
    if (dyn_cast<AllocaInst>(LI->getPointerOperand()))
      return;
    OperandsToUntaint.emplace_back(I, LI->getPointerOperandIndex(), ClInstrumentReads);
  }
  else if (StoreInst *SI = dyn_cast<StoreInst>(I)) {
    if (dyn_cast<AllocaInst>(SI->getPointerOperand()))
      return;
    OperandsToUntaint.emplace_back(I, SI->getPointerOperandIndex(), ClInstrumentWrites);  
  }
  else if (AtomicCmpXchgInst *CmpXchgI = dyn_cast<AtomicCmpXchgInst>(I)) {
    if (dyn_cast<AllocaInst>(CmpXchgI->getPointerOperand()))
      return;
    OperandsToUntaint.emplace_back(I, CmpXchgI->getPointerOperandIndex());
  }
  else if (AtomicRMWInst *RMWI = dyn_cast<AtomicRMWInst>(I)) {
    if (dyn_cast<AllocaInst>(RMWI->getPointerOperand()))
      return;
    OperandsToUntaint.emplace_back(I, RMWI->getPointerOperandIndex());
  }
  else if (CallInst *CI = dyn_cast<CallInst>(I)) {
    Function *Callee = CI->getCalledFunction();

    if (Callee && Callee->isIntrinsic()) {
      switch (Callee->getIntrinsicID()) {
      case Intrinsic::memset:
        if (dyn_cast<AllocaInst>(CI->getArgOperand(0)))
          return;
        OperandsToUntaint.emplace_back(I, 0, ClInstrumentWrites);
        break;
      case Intrinsic::memcpy:
        OperandsToUntaint.emplace_back(I, 0, ClInstrumentWrites);
        OperandsToUntaint.emplace_back(I, 1, ClInstrumentReads);
        break;
      default:
        break;
      }
    }
  }
}

// Detect pointer operands that need to be untainted.
// Also, for each detected pointer operand, determine if
// the corresponding instruction needs to be instrumented.

bool AddressMonitor::monitorFunction(Function &F,
                                     const TargetLibraryInfo &TLI) {
  initialize(*F.getParent());

  bool Res = false;

  const DataLayout &DL = F.getParent()->getDataLayout();

  SmallPtrSet<Value *, 16> TempToInstrument;
  SmallVector<ToUntaint, 16> UntaintList;

  for (auto &BB: F) {
    TempToInstrument.clear();
    for (auto &I: BB) {
      SmallVector<ToUntaint, 2> OperandsToUntaint;
      checkInst(&I, OperandsToUntaint);

      if (!OperandsToUntaint.empty()) {
        for (auto &toUntaint : OperandsToUntaint) {
          if (toUntaint.toInstrument()) {
            Value *Ptr = toUntaint.getPtr();
            if (!TempToInstrument.insert(Ptr).second) {
              // We fail to insert Ptr if we have already seen it in the current BB.
              // Do not instrument it to avoid the overhead.
              toUntaint.setInstrument(false);
            }
          }
          UntaintList.push_back(toUntaint);         
        }
      } else if (dyn_cast<CallBase>(&I)) {
        // A call inside BB.
        TempToInstrument.clear();
      }
    }
  }

  for (auto &toUntaint : UntaintList) {
    untaint(toUntaint, DL);
    Res = true;
  }

  return Res;
}
