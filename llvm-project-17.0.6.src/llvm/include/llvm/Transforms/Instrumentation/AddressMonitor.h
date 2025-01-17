//===- Transforms/Instrumentation/AddressMonitor.h - AMon Pass -----------===//
//
// Author: Farzam Dorostkar
// Email:  farzam.dorostkar@polymtl.ca
// Lab:    DORSAL - Polytechnique Montreal
//
//===--------------------------------------------------------------------===//
//
// This file defines the AddressMonitor (AMon) pass.
//
//===--------------------------------------------------------------------===//

#ifndef LLVM_TRANSFORMS_INSTRUMENTATION_AddressMONITOR_H
#define LLVM_TRANSFORMS_INSTRUMENTATION_AddressMONITOR_H

#include "llvm/IR/PassManager.h"

namespace llvm {
class Function;
class Module;

/// A function pass for AMon instrumentation.
///
/// Instruments functions to detect spatial violations. This function pass
/// inserts ptwrite instrumentation.
struct AddressMonitorPass : public PassInfoMixin<AddressMonitorPass> {
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &FAM);
  static bool isRequired() { return true; }
};

/// A module pass for AMon instrumentation.
///
/// Create ctor and init functions.
struct ModuleAddressMonitorPass
  : public PassInfoMixin<ModuleAddressMonitorPass> {
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
  static bool isRequired() { return true; }
};

} // namespace llvm
#endif /* LLVM_TRANSFORMS_INSTRUMENTATION_AddressMONITOR_H */