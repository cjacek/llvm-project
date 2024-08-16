//===- COFFLinkerContext.h --------------------------------------*- C++ -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#ifndef LLD_COFF_COFFLINKERCONTEXT_H
#define LLD_COFF_COFFLINKERCONTEXT_H

#include "Chunks.h"
#include "Config.h"
#include "DLL.h"
#include "DebugTypes.h"
#include "Driver.h"
#include "InputFiles.h"
#include "SymbolTable.h"
#include "Writer.h"
#include "lld/Common/CommonLinkerContext.h"
#include "lld/Common/Timer.h"

namespace lld::coff {

class COFFTargetContext {
public:
  COFFTargetContext(COFFLinkerContext &ctx) : ctx(ctx), symtab(*this) {}

  llvm::COFF::MachineTypes machine = IMAGE_FILE_MACHINE_UNKNOWN;

  COFFLinkerContext &ctx;
  SymbolTable symtab;
  Symbol *entry = nullptr;

  std::vector<Export> exports;
  llvm::DenseSet<StringRef> directivesExports;
  bool hadExplicitExports;
  EdataContents edata;
  Chunk *edataStart = nullptr;
  Chunk *edataEnd = nullptr;

  Symbol *delayLoadHelper = nullptr;
};

class COFFLinkerContext : public CommonLinkerContext {
public:
  COFFLinkerContext();
  COFFLinkerContext(const COFFLinkerContext &) = delete;
  COFFLinkerContext &operator=(const COFFLinkerContext &) = delete;
  ~COFFLinkerContext() = default;

  LinkerDriver driver;
  COFFOptTable optTable;

  std::vector<ObjFile *> objFileInstances;
  std::map<std::string, PDBInputFile *> pdbInputFileInstances;
  std::vector<ImportFile *> importFileInstances;
  std::vector<BitcodeFile *> bitcodeFileInstances;

  MergeChunk *mergeChunkInstances[Log2MaxSectionAlignment + 1] = {};

  /// All sources of type information in the program.
  std::vector<TpiSource *> tpiSourceList;

  void addTpiSource(TpiSource *tpi) { tpiSourceList.push_back(tpi); }

  std::map<llvm::codeview::GUID, TpiSource *> typeServerSourceMappings;
  std::map<uint32_t, TpiSource *> precompSourceMappings;

  /// List of all output sections. After output sections are finalized, this
  /// can be indexed by getOutputSection.
  std::vector<OutputSection *> outputSections;

  OutputSection *getOutputSection(const Chunk *c) const {
    return c->osidx == 0 ? nullptr : outputSections[c->osidx - 1];
  }

  void addFile(InputFile *file);
  void setMachine(llvm::COFF::MachineTypes machine);

  std::vector<Arm64XDynamicRelocEntry> arm64xRelocs;
  void addArm64XReloc(llvm::COFF::Arm64XFixupType type,
                      lld::coff::Defined *offsetSym,
                      lld::coff::Chunk *offsetChunk, uint16_t offset,
                      lld::coff::Defined *sym, lld::coff::Chunk *chunk,
                      uint64_t value, uint8_t size) {
    arm64xRelocs.emplace_back(type, offsetSym, offsetChunk, offset, sym, chunk,
                              value, size);
  }

  // Returns a list of chunks of selected symbols.
  std::vector<Chunk *> getChunks() const;

  // Fake sections for parsing bitcode files.
  FakeSection ltoTextSection;
  FakeSection ltoDataSection;
  FakeSectionChunk ltoTextSectionChunk;
  FakeSectionChunk ltoDataSectionChunk;

  // All timers used in the COFF linker.
  Timer rootTimer;
  Timer inputFileTimer;
  Timer ltoTimer;
  Timer gcTimer;
  Timer icfTimer;

  // Writer timers.
  Timer codeLayoutTimer;
  Timer outputCommitTimer;
  Timer totalMapTimer;
  Timer symbolGatherTimer;
  Timer symbolStringsTimer;
  Timer writeTimer;

  // PDB timers.
  Timer totalPdbLinkTimer;
  Timer addObjectsTimer;
  Timer typeMergingTimer;
  Timer loadGHashTimer;
  Timer mergeGHashTimer;
  Timer symbolMergingTimer;
  Timer publicsLayoutTimer;
  Timer tpiStreamLayoutTimer;
  Timer diskCommitTimer;

  bool ltoCompilationDone = false;

  Configuration config;
  COFFTargetContext primaryTarget;
  std::optional<COFFTargetContext> hybridTarget;

  void forEachTarget(std::function<void(COFFTargetContext &ctx)> f) {
    f(primaryTarget);
    if (hybridTarget)
      f(*hybridTarget);
  }

  COFFTargetContext &getTarget(llvm::COFF::MachineTypes machine) {
    if (hybridTarget && (machine == ARM64EC || machine == AMD64))
      return *hybridTarget;
    return primaryTarget;
  }
};

} // namespace lld::coff

#endif
