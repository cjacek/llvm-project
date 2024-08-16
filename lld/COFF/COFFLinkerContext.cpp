//===- COFFContext.cpp ----------------------------------------------------===//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Description
//
//===----------------------------------------------------------------------===//

#include "COFFLinkerContext.h"
#include "Symbols.h"
#include "lld/Common/Memory.h"
#include "llvm/BinaryFormat/COFF.h"
#include "llvm/DebugInfo/CodeView/TypeHashing.h"
#include "llvm/Demangle/Demangle.h"
#include "llvm/Object/WindowsMachineFlag.h"

using namespace llvm;
using namespace llvm::COFF;

namespace lld::coff {
COFFLinkerContext::COFFLinkerContext()
    : driver(*this), ltoTextSection(llvm::COFF::IMAGE_SCN_MEM_EXECUTE),
      ltoDataSection(llvm::COFF::IMAGE_SCN_CNT_INITIALIZED_DATA),
      ltoTextSectionChunk(&ltoTextSection.section),
      ltoDataSectionChunk(&ltoDataSection.section),
      rootTimer("Total Linking Time"),
      inputFileTimer("Input File Reading", rootTimer),
      ltoTimer("LTO", rootTimer), gcTimer("GC", rootTimer),
      icfTimer("ICF", rootTimer), codeLayoutTimer("Code Layout", rootTimer),
      outputCommitTimer("Commit Output File", rootTimer),
      totalMapTimer("MAP Emission (Cumulative)", rootTimer),
      symbolGatherTimer("Gather Symbols", totalMapTimer),
      symbolStringsTimer("Build Symbol Strings", totalMapTimer),
      writeTimer("Write to File", totalMapTimer),
      totalPdbLinkTimer("PDB Emission (Cumulative)", rootTimer),
      addObjectsTimer("Add Objects", totalPdbLinkTimer),
      typeMergingTimer("Type Merging", addObjectsTimer),
      loadGHashTimer("Global Type Hashing", addObjectsTimer),
      mergeGHashTimer("GHash Type Merging", addObjectsTimer),
      symbolMergingTimer("Symbol Merging", addObjectsTimer),
      publicsLayoutTimer("Publics Stream Layout", totalPdbLinkTimer),
      tpiStreamLayoutTimer("TPI Stream Layout", totalPdbLinkTimer),
      diskCommitTimer("Commit to Disk", totalPdbLinkTimer),
      primaryTarget(*this) {}

static bool compatibleMachineType(COFFLinkerContext &ctx, MachineTypes mt) {
  if (mt == IMAGE_FILE_MACHINE_UNKNOWN)
    return true;
  switch (ctx.config.machine) {
  case ARM64:
    return mt == ARM64 || mt == ARM64X;
  case ARM64EC:
    return isArm64EC(mt) || mt == AMD64;
  case ARM64X:
    return isAnyArm64(mt) || mt == AMD64;
  default:
    return ctx.config.machine == mt;
  }
}

void COFFLinkerContext::addFile(InputFile *file) {
  log("Reading " + toString(file));
  if (file->lazy) {
    if (auto *f = dyn_cast<BitcodeFile>(file))
      f->parseLazy();
    else
      cast<ObjFile>(file)->parseLazy();
  } else {
    file->parse();
    if (auto *f = dyn_cast<ObjFile>(file)) {
      objFileInstances.push_back(f);
    } else if (auto *f = dyn_cast<BitcodeFile>(file)) {
      if (ltoCompilationDone) {
        error("LTO object file " + toString(file) +
              " linked in after doing LTO compilation.");
      }
      bitcodeFileInstances.push_back(f);
    } else if (auto *f = dyn_cast<ImportFile>(file)) {
      importFileInstances.push_back(f);
    }
  }
  MachineTypes mt = file->getMachineType();
  if (config.machine == IMAGE_FILE_MACHINE_UNKNOWN) {
    setMachine(mt);
  } else if (!compatibleMachineType(*this, mt)) {
    error(toString(file) + ": machine type " + machineToStr(mt) +
          " conflicts with " + machineToStr(config.machine));
    return;
  }

  driver.parseDirectives(file);
}

void COFFLinkerContext::setMachine(MachineTypes machine) {
  assert(config.machine == IMAGE_FILE_MACHINE_UNKNOWN);
  if (machine == IMAGE_FILE_MACHINE_UNKNOWN)
    return;

  config.machine = machine;

  if (machine != ARM64X) {
    primaryTarget.machine = machine;
  } else {
    primaryTarget.machine = ARM64;
    hybridTarget.emplace(*this);
    hybridTarget->machine = ARM64EC;
  }

  driver.addWinSysRootLibSearchPaths();
}

std::vector<Chunk *> COFFLinkerContext::getChunks() const {
  std::vector<Chunk *> res;
  for (ObjFile *file : objFileInstances) {
    ArrayRef<Chunk *> v = file->getChunks();
    res.insert(res.end(), v.begin(), v.end());
  }
  return res;
}

} // namespace lld::coff
