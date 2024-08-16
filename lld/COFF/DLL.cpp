//===- DLL.cpp ------------------------------------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// This file defines various types of chunks for the DLL import or export
// descriptor tables. They are inherently Windows-specific.
// You need to read Microsoft PE/COFF spec to understand details
// about the data structures.
//
// If you are not particularly interested in linking against Windows
// DLL, you can skip this file, and you should still be able to
// understand the rest of the linker.
//
//===----------------------------------------------------------------------===//

#include "DLL.h"
#include "COFFLinkerContext.h"
#include "Chunks.h"
#include "SymbolTable.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/Object/COFF.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/Path.h"

using namespace llvm;
using namespace llvm::object;
using namespace llvm::support::endian;
using namespace llvm::COFF;

namespace lld::coff {
namespace {

// Import table

// A chunk for the import descriptor table.
class HintNameChunk : public NonSectionChunk {
public:
  HintNameChunk(StringRef n, uint16_t h) : name(n), hint(h) {}

  size_t getSize() const override {
    // Starts with 2 byte Hint field, followed by a null-terminated string,
    // ends with 0 or 1 byte padding.
    return alignTo(name.size() + 3, 2);
  }

  void writeTo(uint8_t *buf) const override {
    memset(buf, 0, getSize());
    write16le(buf, hint);
    memcpy(buf + 2, name.data(), name.size());
  }

private:
  StringRef name;
  uint16_t hint;
};

// A chunk for the import descriptor table.
class LookupChunk : public NonSectionChunk {
public:
  explicit LookupChunk(COFFLinkerContext &ctx, Chunk *c)
      : hintName(c), ctx(ctx) {
    setAlignment(ctx.config.wordsize);
  }
  size_t getSize() const override { return ctx.config.wordsize; }

  void writeTo(uint8_t *buf) const override {
    if (ctx.config.is64())
      write64le(buf, hintName->getRVA());
    else
      write32le(buf, hintName->getRVA());
  }

  Chunk *hintName;

private:
  COFFLinkerContext &ctx;
};

// A chunk for the import descriptor table.
// This chunk represent import-by-ordinal symbols.
// See Microsoft PE/COFF spec 7.1. Import Header for details.
class OrdinalOnlyChunk : public NonSectionChunk {
public:
  explicit OrdinalOnlyChunk(COFFLinkerContext &c, uint16_t v)
      : ordinal(v), ctx(c) {
    setAlignment(ctx.config.wordsize);
  }
  size_t getSize() const override { return ctx.config.wordsize; }

  void writeTo(uint8_t *buf) const override {
    // An import-by-ordinal slot has MSB 1 to indicate that
    // this is import-by-ordinal (and not import-by-name).
    if (ctx.config.is64()) {
      write64le(buf, (1ULL << 63) | ordinal);
    } else {
      write32le(buf, (1ULL << 31) | ordinal);
    }
  }

  uint16_t ordinal;

private:
  COFFLinkerContext &ctx;
};

// A chunk for the import descriptor table.
class ImportDirectoryChunk : public NonSectionChunk {
public:
  explicit ImportDirectoryChunk(Chunk *n) : dllName(n) { setAlignment(4); }
  size_t getSize() const override { return sizeof(ImportDirectoryTableEntry); }

  void writeTo(uint8_t *buf) const override {
    memset(buf, 0, getSize());

    auto *e = (coff_import_directory_table_entry *)(buf);
    e->ImportLookupTableRVA = lookupTab->getRVA();
    e->NameRVA = dllName->getRVA();
    e->ImportAddressTableRVA = addressTab->getRVA();
  }

  Chunk *dllName;
  Chunk *lookupTab;
  Chunk *addressTab;
};

// A chunk representing null terminator in the import table.
// Contents of this chunk is always null bytes.
class NullChunk : public NonSectionChunk {
public:
  explicit NullChunk(size_t n) : size(n) { hasData = false; }
  size_t getSize() const override { return size; }

  void writeTo(uint8_t *buf) const override {
    memset(buf, 0, size);
  }

private:
  size_t size;
};

// A chunk for ARM64EC auxiliary IAT.
class AuxImportChunk : public NonSectionChunk {
public:
  explicit AuxImportChunk(COFFLinkerContext &ctx, Chunk *c) : ctx(ctx), thunkChunk(c) {
    setAlignment(sizeof(uint64_t));
  }
  size_t getSize() const override { return sizeof(uint64_t); }

  void writeTo(uint8_t *buf) const override {
    write64le(buf, thunkChunk ? thunkChunk->getRVA() + ctx.config.imageBase : 0);
  }

  void getBaserels(std::vector<Baserel> *res) override {
    if (thunkChunk)
      res->emplace_back(rva, ARM64EC);
  }

private:
  COFFLinkerContext &ctx;
  Chunk *thunkChunk;
};

static std::vector<std::vector<DefinedImportData *>>
binImports(COFFLinkerContext &ctx,
           const std::vector<DefinedImportData *> &imports, bool mergeHybrid) {
  // Group DLL-imported symbols by DLL name because that's how
  // symbols are laid out in the import descriptor table.
  auto less = [&ctx](const std::string &a, const std::string &b) {
    return ctx.config.dllOrder[a] < ctx.config.dllOrder[b];
  };
  std::map<std::string, std::vector<DefinedImportData *>, decltype(less)> m(
      less);
  for (DefinedImportData *sym : imports)
    m[sym->getDLLName().lower()].push_back(sym);

  std::vector<std::vector<DefinedImportData *>> v;
  for (auto &kv : m) {
    // Sort symbols by name for each group.
    std::vector<DefinedImportData *> &syms = kv.second;
    llvm::sort(syms, [](DefinedImportData *a, DefinedImportData *b) {
      auto getBaseName = [](DefinedImportData *sym) {
        StringRef name = sym->getName();
        name.consume_front("__imp_");
        // Skip aux_ part of ARM64EC function symbol name.
        if (sym->file->impchkThunk)
          name.consume_front("aux_");
        return name;
      };
      return getBaseName(a) < getBaseName(b);
    });
    if (!ctx.hybridTarget || syms.empty()) {
      v.push_back(std::move(syms));
    } else if (mergeHybrid) {
      std::vector<DefinedImportData *> hybridSyms;
      hybridSyms.push_back(syms[0]);
      for (size_t i = 1; i < syms.size(); ++i) {
        ImportFile *file = syms[i]->file;
        ImportFile *prev = hybridSyms.back()->file;
        if (prev->hybridFile || !file->matches(prev)) {
          hybridSyms.push_back(syms[i]);
          continue;
        }

        if (isArm64EC(file->getMachineType())) {
          hybridSyms.pop_back();
          hybridSyms.push_back(syms[i]);
        }

        prev->hybridFile = file;
        file->hybridFile = prev;
      }

      llvm::stable_sort(hybridSyms,
                        [](DefinedImportData *a, DefinedImportData *b) {
                          if (a->file->hybridFile)
                            return !b->file->hybridFile && b->file->isEC();
                          return !a->file->isEC() && b->file->isEC();
                        });
      v.push_back(std::move(hybridSyms));
    } else {
      llvm::stable_sort(syms, [](DefinedImportData *a, DefinedImportData *b) {
        return !a->file->isEC() && b->file->isEC();
      });
      v.push_back(std::move(syms));
    }
  }
  return v;
}

// See Microsoft PE/COFF spec 4.3 for details.

// A chunk for the delay import descriptor table etnry.
class DelayDirectoryChunk : public NonSectionChunk {
public:
  explicit DelayDirectoryChunk(Chunk *n) : dllName(n) { setAlignment(4); }

  size_t getSize() const override {
    return sizeof(delay_import_directory_table_entry);
  }

  void writeTo(uint8_t *buf) const override {
    memset(buf, 0, getSize());

    auto *e = (delay_import_directory_table_entry *)(buf);
    e->Attributes = 1;
    e->Name = dllName->getRVA();
    e->ModuleHandle = moduleHandle->getRVA();
    e->DelayImportAddressTable = addressTab->getRVA();
    e->DelayImportNameTable = nameTab->getRVA();
  }

  Chunk *dllName;
  Chunk *moduleHandle;
  Chunk *addressTab;
  Chunk *nameTab;
};

// Initial contents for delay-loaded functions.
// This code calls __delayLoadHelper2 function to resolve a symbol
// which then overwrites its jump table slot with the result
// for subsequent function calls.
static const uint8_t thunkX64[] = {
    0x48, 0x8D, 0x05, 0, 0, 0, 0,       // lea     rax, [__imp_<FUNCNAME>]
    0xE9, 0, 0, 0, 0,                   // jmp     __tailMerge_<lib>
};

static const uint8_t tailMergeX64[] = {
    0x51,                               // push    rcx
    0x52,                               // push    rdx
    0x41, 0x50,                         // push    r8
    0x41, 0x51,                         // push    r9
    0x48, 0x83, 0xEC, 0x48,             // sub     rsp, 48h
    0x66, 0x0F, 0x7F, 0x04, 0x24,       // movdqa  xmmword ptr [rsp], xmm0
    0x66, 0x0F, 0x7F, 0x4C, 0x24, 0x10, // movdqa  xmmword ptr [rsp+10h], xmm1
    0x66, 0x0F, 0x7F, 0x54, 0x24, 0x20, // movdqa  xmmword ptr [rsp+20h], xmm2
    0x66, 0x0F, 0x7F, 0x5C, 0x24, 0x30, // movdqa  xmmword ptr [rsp+30h], xmm3
    0x48, 0x8B, 0xD0,                   // mov     rdx, rax
    0x48, 0x8D, 0x0D, 0, 0, 0, 0,       // lea     rcx, [___DELAY_IMPORT_...]
    0xE8, 0, 0, 0, 0,                   // call    __delayLoadHelper2
    0x66, 0x0F, 0x6F, 0x04, 0x24,       // movdqa  xmm0, xmmword ptr [rsp]
    0x66, 0x0F, 0x6F, 0x4C, 0x24, 0x10, // movdqa  xmm1, xmmword ptr [rsp+10h]
    0x66, 0x0F, 0x6F, 0x54, 0x24, 0x20, // movdqa  xmm2, xmmword ptr [rsp+20h]
    0x66, 0x0F, 0x6F, 0x5C, 0x24, 0x30, // movdqa  xmm3, xmmword ptr [rsp+30h]
    0x48, 0x83, 0xC4, 0x48,             // add     rsp, 48h
    0x41, 0x59,                         // pop     r9
    0x41, 0x58,                         // pop     r8
    0x5A,                               // pop     rdx
    0x59,                               // pop     rcx
    0xFF, 0xE0,                         // jmp     rax
};

static const uint8_t tailMergeUnwindInfoX64[] = {
    0x01,       // Version=1, Flags=UNW_FLAG_NHANDLER
    0x0a,       // Size of prolog
    0x05,       // Count of unwind codes
    0x00,       // No frame register
    0x0a, 0x82, // Offset 0xa: UWOP_ALLOC_SMALL(0x48)
    0x06, 0x02, // Offset 6: UWOP_ALLOC_SMALL(8)
    0x04, 0x02, // Offset 4: UWOP_ALLOC_SMALL(8)
    0x02, 0x02, // Offset 2: UWOP_ALLOC_SMALL(8)
    0x01, 0x02, // Offset 1: UWOP_ALLOC_SMALL(8)
    0x00, 0x00  // Padding to align on 32-bits
};

static const uint8_t thunkX86[] = {
    0xB8, 0, 0, 0, 0,  // mov   eax, offset ___imp__<FUNCNAME>
    0xE9, 0, 0, 0, 0,  // jmp   __tailMerge_<lib>
};

static const uint8_t tailMergeX86[] = {
    0x51,              // push  ecx
    0x52,              // push  edx
    0x50,              // push  eax
    0x68, 0, 0, 0, 0,  // push  offset ___DELAY_IMPORT_DESCRIPTOR_<DLLNAME>_dll
    0xE8, 0, 0, 0, 0,  // call  ___delayLoadHelper2@8
    0x5A,              // pop   edx
    0x59,              // pop   ecx
    0xFF, 0xE0,        // jmp   eax
};

static const uint8_t thunkARM[] = {
    0x40, 0xf2, 0x00, 0x0c, // mov.w   ip, #0 __imp_<FUNCNAME>
    0xc0, 0xf2, 0x00, 0x0c, // mov.t   ip, #0 __imp_<FUNCNAME>
    0x00, 0xf0, 0x00, 0xb8, // b.w     __tailMerge_<lib>
};

static const uint8_t tailMergeARM[] = {
    0x2d, 0xe9, 0x0f, 0x48, // push.w  {r0, r1, r2, r3, r11, lr}
    0x0d, 0xf2, 0x10, 0x0b, // addw    r11, sp, #16
    0x2d, 0xed, 0x10, 0x0b, // vpush   {d0, d1, d2, d3, d4, d5, d6, d7}
    0x61, 0x46,             // mov     r1, ip
    0x40, 0xf2, 0x00, 0x00, // mov.w   r0, #0 DELAY_IMPORT_DESCRIPTOR
    0xc0, 0xf2, 0x00, 0x00, // mov.t   r0, #0 DELAY_IMPORT_DESCRIPTOR
    0x00, 0xf0, 0x00, 0xd0, // bl      #0 __delayLoadHelper2
    0x84, 0x46,             // mov     ip, r0
    0xbd, 0xec, 0x10, 0x0b, // vpop    {d0, d1, d2, d3, d4, d5, d6, d7}
    0xbd, 0xe8, 0x0f, 0x48, // pop.w   {r0, r1, r2, r3, r11, lr}
    0x60, 0x47,             // bx      ip
};

static const uint8_t thunkARM64[] = {
    0x11, 0x00, 0x00, 0x90, // adrp    x17, #0      __imp_<FUNCNAME>
    0x31, 0x02, 0x00, 0x91, // add     x17, x17, #0 :lo12:__imp_<FUNCNAME>
    0x00, 0x00, 0x00, 0x14, // b       __tailMerge_<lib>
};

static const uint8_t tailMergeARM64[] = {
    0xfd, 0x7b, 0xb3, 0xa9, // stp     x29, x30, [sp, #-208]!
    0xfd, 0x03, 0x00, 0x91, // mov     x29, sp
    0xe0, 0x07, 0x01, 0xa9, // stp     x0, x1, [sp, #16]
    0xe2, 0x0f, 0x02, 0xa9, // stp     x2, x3, [sp, #32]
    0xe4, 0x17, 0x03, 0xa9, // stp     x4, x5, [sp, #48]
    0xe6, 0x1f, 0x04, 0xa9, // stp     x6, x7, [sp, #64]
    0xe0, 0x87, 0x02, 0xad, // stp     q0, q1, [sp, #80]
    0xe2, 0x8f, 0x03, 0xad, // stp     q2, q3, [sp, #112]
    0xe4, 0x97, 0x04, 0xad, // stp     q4, q5, [sp, #144]
    0xe6, 0x9f, 0x05, 0xad, // stp     q6, q7, [sp, #176]
    0xe1, 0x03, 0x11, 0xaa, // mov     x1, x17
    0x00, 0x00, 0x00, 0x90, // adrp    x0, #0     DELAY_IMPORT_DESCRIPTOR
    0x00, 0x00, 0x00, 0x91, // add     x0, x0, #0 :lo12:DELAY_IMPORT_DESCRIPTOR
    0x00, 0x00, 0x00, 0x94, // bl      #0 __delayLoadHelper2
    0xf0, 0x03, 0x00, 0xaa, // mov     x16, x0
    0xe6, 0x9f, 0x45, 0xad, // ldp     q6, q7, [sp, #176]
    0xe4, 0x97, 0x44, 0xad, // ldp     q4, q5, [sp, #144]
    0xe2, 0x8f, 0x43, 0xad, // ldp     q2, q3, [sp, #112]
    0xe0, 0x87, 0x42, 0xad, // ldp     q0, q1, [sp, #80]
    0xe6, 0x1f, 0x44, 0xa9, // ldp     x6, x7, [sp, #64]
    0xe4, 0x17, 0x43, 0xa9, // ldp     x4, x5, [sp, #48]
    0xe2, 0x0f, 0x42, 0xa9, // ldp     x2, x3, [sp, #32]
    0xe0, 0x07, 0x41, 0xa9, // ldp     x0, x1, [sp, #16]
    0xfd, 0x7b, 0xcd, 0xa8, // ldp     x29, x30, [sp], #208
    0x00, 0x02, 0x1f, 0xd6, // br      x16
};

static const uint8_t thunkARM64EC[] = {
    0x11, 0x00, 0x00, 0x90, // adrp    x17, #0      __imp_aux_<FUNCNAME>
    0x31, 0x02, 0x00, 0x91, // add     x17, x17, #0 :lo12:__imp_aux_<FUNCNAME>
    0xfe, 0x0f, 0x1f, 0xf8, // str     x30, [sp, #-0x10]!
    0x00, 0x00, 0x00, 0x94, // bl      __tailMerge_<lib>
    0xfe, 0x07, 0x41, 0xf8, // ldr     x30, [sp], #0x10
    0x08, 0x00, 0x00, 0x90, // adrp    x0, __impchk_<FUNCNAME>
    0x08, 0x01, 0x00, 0x91, // add     x0, x0, :lo12:__impchk_<FUNCNAME>
    0x09, 0x00, 0x00, 0x90, // adrp    x0, __imp_<FUNCNAME>
    0x28, 0x01, 0x00, 0xf9, // str     x8, [x9, :lo12:__imp_<FUNCNAME>]
    0x00, 0x01, 0x1f, 0xd6, // br      x8
};

static const uint8_t delayHelperARM64EC[] = {
    0xfd, 0x7b, 0xb3, 0xa9, // stp     x29, x30, [sp, #-208]!
    0xfd, 0x03, 0x00, 0x91, // mov     x29, sp
    0xe0, 0x07, 0x01, 0xa9, // stp     x0, x1, [sp, #16]
    0xe2, 0x0f, 0x02, 0xa9, // stp     x2, x3, [sp, #32]
    0xe4, 0x17, 0x03, 0xa9, // stp     x4, x5, [sp, #48]
    0xe6, 0x1f, 0x04, 0xa9, // stp     x6, x7, [sp, #64]
    0xe0, 0x87, 0x02, 0xad, // stp     q0, q1, [sp, #80]
    0xe2, 0x8f, 0x03, 0xad, // stp     q2, q3, [sp, #112]
    0xe4, 0x97, 0x04, 0xad, // stp     q4, q5, [sp, #144]
    0xe6, 0x9f, 0x05, 0xad, // stp     q6, q7, [sp, #176]
    0xe1, 0x03, 0x11, 0xaa, // mov     x1, x17
    0x00, 0x00, 0x00, 0x90, // adrp    x0, #0     DELAY_IMPORT_DESCRIPTOR
    0x00, 0x00, 0x00, 0x91, // add     x0, x0, #0 :lo12:DELAY_IMPORT_DESCRIPTOR
    0x00, 0x00, 0x00, 0x94, // bl      #0 __delayLoadHelper2
    0xe6, 0x9f, 0x45, 0xad, // ldp     q6, q7, [sp, #176]
    0xe4, 0x97, 0x44, 0xad, // ldp     q4, q5, [sp, #144]
    0xe2, 0x8f, 0x43, 0xad, // ldp     q2, q3, [sp, #112]
    0xe0, 0x87, 0x42, 0xad, // ldp     q0, q1, [sp, #80]
    0xe6, 0x1f, 0x44, 0xa9, // ldp     x6, x7, [sp, #64]
    0xe4, 0x17, 0x43, 0xa9, // ldp     x4, x5, [sp, #48]
    0xe2, 0x0f, 0x42, 0xa9, // ldp     x2, x3, [sp, #32]
    0xe0, 0x07, 0x41, 0xa9, // ldp     x0, x1, [sp, #16]
    0xfd, 0x7b, 0xcd, 0xa8, // ldp     x29, x30, [sp], #208
    0xc0, 0x03, 0x5f, 0xd6, // ret
};

// A chunk for the delay import thunk.
class ThunkChunkX64 : public NonSectionCodeChunk {
public:
  ThunkChunkX64(Defined *i, Chunk *tm) : imp(i), tailMerge(tm) {}

  size_t getSize() const override { return sizeof(thunkX64); }
  MachineTypes getMachine() const override { return AMD64; }

  void writeTo(uint8_t *buf) const override {
    memcpy(buf, thunkX64, sizeof(thunkX64));
    write32le(buf + 3, imp->getRVA() - rva - 7);
    write32le(buf + 8, tailMerge->getRVA() - rva - 12);
  }

  Defined *imp = nullptr;
  Chunk *tailMerge = nullptr;
};

class TailMergeChunkX64 : public NonSectionCodeChunk {
public:
  TailMergeChunkX64(Chunk *d, Defined *h) : desc(d), helper(h) {}

  size_t getSize() const override { return sizeof(tailMergeX64); }
  MachineTypes getMachine() const override { return AMD64; }

  void writeTo(uint8_t *buf) const override {
    memcpy(buf, tailMergeX64, sizeof(tailMergeX64));
    write32le(buf + 39, desc->getRVA() - rva - 43);
    write32le(buf + 44, helper->getRVA() - rva - 48);
  }

  Chunk *desc = nullptr;
  Defined *helper = nullptr;
};

class TailMergePDataChunkX64 : public NonSectionChunk {
public:
  TailMergePDataChunkX64(Chunk *tm, Chunk *unwind) : tm(tm), unwind(unwind) {
    // See
    // https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64#struct-runtime_function
    setAlignment(4);
  }

  size_t getSize() const override { return 3 * sizeof(uint32_t); }

  void writeTo(uint8_t *buf) const override {
    write32le(buf + 0, tm->getRVA()); // TailMergeChunk start RVA
    write32le(buf + 4, tm->getRVA() + tm->getSize()); // TailMergeChunk stop RVA
    write32le(buf + 8, unwind->getRVA());             // UnwindInfo RVA
  }

  Chunk *tm = nullptr;
  Chunk *unwind = nullptr;
};

class TailMergeUnwindInfoX64 : public NonSectionChunk {
public:
  TailMergeUnwindInfoX64() {
    // See
    // https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64#struct-unwind_info
    setAlignment(4);
  }

  size_t getSize() const override { return sizeof(tailMergeUnwindInfoX64); }

  void writeTo(uint8_t *buf) const override {
    memcpy(buf, tailMergeUnwindInfoX64, sizeof(tailMergeUnwindInfoX64));
  }
};

class ThunkChunkX86 : public NonSectionCodeChunk {
public:
  ThunkChunkX86(COFFLinkerContext &ctx, Defined *i, Chunk *tm)
      : imp(i), tailMerge(tm), ctx(ctx) {}

  size_t getSize() const override { return sizeof(thunkX86); }
  MachineTypes getMachine() const override { return I386; }

  void writeTo(uint8_t *buf) const override {
    memcpy(buf, thunkX86, sizeof(thunkX86));
    write32le(buf + 1, imp->getRVA() + ctx.config.imageBase);
    write32le(buf + 6, tailMerge->getRVA() - rva - 10);
  }

  void getBaserels(std::vector<Baserel> *res) override {
    res->emplace_back(rva + 1, getMachine());
  }

  Defined *imp = nullptr;
  Chunk *tailMerge = nullptr;

private:
  const COFFLinkerContext &ctx;
};

class TailMergeChunkX86 : public NonSectionCodeChunk {
public:
  TailMergeChunkX86(COFFLinkerContext &ctx, Chunk *d, Defined *h)
      : desc(d), helper(h), ctx(ctx) {}

  size_t getSize() const override { return sizeof(tailMergeX86); }
  MachineTypes getMachine() const override { return I386; }

  void writeTo(uint8_t *buf) const override {
    memcpy(buf, tailMergeX86, sizeof(tailMergeX86));
    write32le(buf + 4, desc->getRVA() + ctx.config.imageBase);
    write32le(buf + 9, helper->getRVA() - rva - 13);
  }

  void getBaserels(std::vector<Baserel> *res) override {
    res->emplace_back(rva + 4, getMachine());
  }

  Chunk *desc = nullptr;
  Defined *helper = nullptr;

private:
  const COFFLinkerContext &ctx;
};

class ThunkChunkARM : public NonSectionCodeChunk {
public:
  ThunkChunkARM(COFFLinkerContext &ctx, Defined *i, Chunk *tm)
      : imp(i), tailMerge(tm), ctx(ctx) {
    setAlignment(2);
  }

  size_t getSize() const override { return sizeof(thunkARM); }
  MachineTypes getMachine() const override { return ARMNT; }

  void writeTo(uint8_t *buf) const override {
    memcpy(buf, thunkARM, sizeof(thunkARM));
    applyMOV32T(buf + 0, imp->getRVA() + ctx.config.imageBase);
    applyBranch24T(buf + 8, tailMerge->getRVA() - rva - 12);
  }

  void getBaserels(std::vector<Baserel> *res) override {
    res->emplace_back(rva + 0, IMAGE_REL_BASED_ARM_MOV32T);
  }

  Defined *imp = nullptr;
  Chunk *tailMerge = nullptr;

private:
  const COFFLinkerContext &ctx;
};

class TailMergeChunkARM : public NonSectionCodeChunk {
public:
  TailMergeChunkARM(COFFLinkerContext &ctx, Chunk *d, Defined *h)
      : desc(d), helper(h), ctx(ctx) {
    setAlignment(2);
  }

  size_t getSize() const override { return sizeof(tailMergeARM); }
  MachineTypes getMachine() const override { return ARMNT; }

  void writeTo(uint8_t *buf) const override {
    memcpy(buf, tailMergeARM, sizeof(tailMergeARM));
    applyMOV32T(buf + 14, desc->getRVA() + ctx.config.imageBase);
    applyBranch24T(buf + 22, helper->getRVA() - rva - 26);
  }

  void getBaserels(std::vector<Baserel> *res) override {
    res->emplace_back(rva + 14, IMAGE_REL_BASED_ARM_MOV32T);
  }

  Chunk *desc = nullptr;
  Defined *helper = nullptr;

private:
  const COFFLinkerContext &ctx;
};

class ThunkChunkARM64 : public NonSectionCodeChunk {
public:
  ThunkChunkARM64(Defined *i, Chunk *tm) : imp(i), tailMerge(tm) {
    setAlignment(4);
  }

  size_t getSize() const override { return sizeof(thunkARM64); }
  MachineTypes getMachine() const override { return ARM64; }

  void writeTo(uint8_t *buf) const override {
    memcpy(buf, thunkARM64, sizeof(thunkARM64));
    applyArm64Addr(buf + 0, imp->getRVA(), rva + 0, 12);
    applyArm64Imm(buf + 4, imp->getRVA() & 0xfff, 0);
    applyArm64Branch26(buf + 8, tailMerge->getRVA() - rva - 8);
  }

  Defined *imp = nullptr;
  Chunk *tailMerge = nullptr;
};

class TailMergeChunkARM64 : public NonSectionCodeChunk {
public:
  TailMergeChunkARM64(Chunk *d, Defined *h) : desc(d), helper(h) {
    setAlignment(4);
  }

  size_t getSize() const override { return sizeof(tailMergeARM64); }
  MachineTypes getMachine() const override { return ARM64; }

  void writeTo(uint8_t *buf) const override {
    memcpy(buf, tailMergeARM64, sizeof(tailMergeARM64));
    applyArm64Addr(buf + 44, desc->getRVA(), rva + 44, 12);
    applyArm64Imm(buf + 48, desc->getRVA() & 0xfff, 0);
    applyArm64Branch26(buf + 52, helper->getRVA() - rva - 52);
  }

  Chunk *desc = nullptr;
  Defined *helper = nullptr;
};

class ThunkChunkARM64EC : public NonSectionCodeChunk {
public:
  ThunkChunkARM64EC(ImportFile *f, Chunk *tm) : file(f), tailMerge(tm) {
    setAlignment(4);
  }

  size_t getSize() const override { return sizeof(thunkARM64EC); }
  MachineTypes getMachine() const override { return ARM64EC; }

  void writeTo(uint8_t *buf) const override {
    memcpy(buf, thunkARM64EC, sizeof(thunkARM64EC));
    applyArm64Addr(buf + 0, file->impSym->getRVA(), rva + 0, 12);
    applyArm64Imm(buf + 4, file->impSym->getRVA() & 0xfff, 0);
    applyArm64Branch26(buf + 12, tailMerge->getRVA() - rva - 12);
    applyArm64Addr(buf + 20, file->impchkThunk->getRVA(), rva + 20, 12);
    applyArm64Imm(buf + 24, file->impchkThunk->getRVA() & 0xfff, 0);
    applyArm64Addr(buf + 28, file->impECSym->getRVA(), rva + 28, 12);
    applyArm64Ldr(buf + 32, file->impECSym->getRVA() & 0xfff);
  }

  ImportFile *file;
  Chunk *tailMerge;
};

class DelayHelperChunkARM64EC : public NonSectionCodeChunk {
public:
  DelayHelperChunkARM64EC(Chunk *d, Defined *h) : desc(d), helper(h) {
    setAlignment(4);
  }

  size_t getSize() const override { return sizeof(delayHelperARM64EC); }
  MachineTypes getMachine() const override { return ARM64EC; }

  void writeTo(uint8_t *buf) const override {
    memcpy(buf, delayHelperARM64EC, sizeof(delayHelperARM64EC));
    applyArm64Addr(buf + 44, desc->getRVA(), rva + 44, 12);
    applyArm64Imm(buf + 48, desc->getRVA() & 0xfff, 0);
    applyArm64Branch26(buf + 52, helper->getRVA() - rva - 52);
  }

  Chunk *desc = nullptr;
  Defined *helper = nullptr;
};

// A chunk for the import descriptor table.
class DelayAddressChunk : public NonSectionChunk {
public:
  explicit DelayAddressChunk(COFFLinkerContext &ctx, Chunk *c)
      : thunk(c), ctx(ctx) {
    setAlignment(ctx.config.wordsize);
  }
  size_t getSize() const override { return ctx.config.wordsize; }

  void writeTo(uint8_t *buf) const override {
    if (ctx.config.is64()) {
      write64le(buf, thunk->getRVA() + ctx.config.imageBase);
    } else {
      uint32_t bit = 0;
      // Pointer to thumb code must have the LSB set, so adjust it.
      if (ctx.config.machine == ARMNT)
        bit = 1;
      write32le(buf, (thunk->getRVA() + ctx.config.imageBase) | bit);
    }
  }

  void getBaserels(std::vector<Baserel> *res) override {
    res->emplace_back(rva, ctx.config.machine);
  }

  Chunk *thunk;

private:
  const COFFLinkerContext &ctx;
};

// Export table
// Read Microsoft PE/COFF spec 5.3 for details.

// A chunk for the export descriptor table.
class ExportDirectoryChunk : public NonSectionChunk {
public:
  ExportDirectoryChunk(int baseOrdinal, int maxOrdinal, int nameTabSize,
                       Chunk *d, Chunk *a, Chunk *n, Chunk *o)
      : baseOrdinal(baseOrdinal), maxOrdinal(maxOrdinal),
        nameTabSize(nameTabSize), dllName(d), addressTab(a), nameTab(n),
        ordinalTab(o) {}

  size_t getSize() const override {
    return sizeof(export_directory_table_entry);
  }

  void writeTo(uint8_t *buf) const override {
    memset(buf, 0, getSize());

    auto *e = (export_directory_table_entry *)(buf);
    e->NameRVA = dllName->getRVA();
    e->OrdinalBase = baseOrdinal;
    e->AddressTableEntries = (maxOrdinal - baseOrdinal) + 1;
    e->NumberOfNamePointers = nameTabSize;
    e->ExportAddressTableRVA = addressTab->getRVA();
    e->NamePointerRVA = nameTab->getRVA();
    e->OrdinalTableRVA = ordinalTab->getRVA();
  }

  uint16_t baseOrdinal;
  uint16_t maxOrdinal;
  uint16_t nameTabSize;
  Chunk *dllName;
  Chunk *addressTab;
  Chunk *nameTab;
  Chunk *ordinalTab;
};

class AddressTableChunk : public NonSectionChunk {
public:
  explicit AddressTableChunk(COFFTargetContext &target, size_t baseOrdinal,
                             size_t maxOrdinal)
      : baseOrdinal(baseOrdinal), size((maxOrdinal - baseOrdinal) + 1),
        target(target) {}
  size_t getSize() const override { return size * 4; }

  void writeTo(uint8_t *buf) const override {
    memset(buf, 0, getSize());

    for (const Export &e : target.exports) {
      assert(e.ordinal >= baseOrdinal && "Export symbol has invalid ordinal");
      // Subtract the OrdinalBase to get the index.
      uint8_t *p = buf + (e.ordinal - baseOrdinal) * 4;
      uint32_t bit = 0;
      // Pointer to thumb code must have the LSB set, so adjust it.
      if (target.machine == ARMNT && !e.data)
        bit = 1;
      if (e.forwardChunk) {
        write32le(p, e.forwardChunk->getRVA() | bit);
      } else {
        assert(cast<Defined>(e.sym)->getRVA() != 0 &&
               "Exported symbol unmapped");
        write32le(p, cast<Defined>(e.sym)->getRVA() | bit);
      }
    }
  }

private:
  size_t baseOrdinal;
  size_t size;
  const COFFTargetContext &target;
};

class NamePointersChunk : public NonSectionChunk {
public:
  explicit NamePointersChunk(std::vector<Chunk *> &v) : chunks(v) {}
  size_t getSize() const override { return chunks.size() * 4; }

  void writeTo(uint8_t *buf) const override {
    for (Chunk *c : chunks) {
      write32le(buf, c->getRVA());
      buf += 4;
    }
  }

private:
  std::vector<Chunk *> chunks;
};

class ExportOrdinalChunk : public NonSectionChunk {
public:
  explicit ExportOrdinalChunk(const COFFTargetContext &target,
                              size_t baseOrdinal, size_t tableSize)
      : baseOrdinal(baseOrdinal), size(tableSize), target(target) {}
  size_t getSize() const override { return size * 2; }

  void writeTo(uint8_t *buf) const override {
    for (const Export &e : target.exports) {
      if (e.noname)
        continue;
      assert(e.ordinal >= baseOrdinal && "Export symbol has invalid ordinal");
      // This table stores unbiased indices, so subtract OrdinalBase.
      write16le(buf, e.ordinal - baseOrdinal);
      buf += 2;
    }
  }

private:
  size_t baseOrdinal;
  size_t size;
  const COFFTargetContext &target;
};

} // anonymous namespace

void IdataContents::create(COFFLinkerContext &ctx) {
  std::vector<std::vector<DefinedImportData *>> v =
      binImports(ctx, imports, true);

  // Create .idata contents for each DLL.
  for (std::vector<DefinedImportData *> &syms : v) {
    // Create lookup and address tables. If they have external names,
    // we need to create hintName chunks to store the names.
    // If they don't (if they are import-by-ordinals), we store only
    // ordinal values to the table.
    size_t base = lookups.size();
    Chunk *lookupsTerminator = nullptr, *addressesTerminator = nullptr;
    for (DefinedImportData *s : syms) {
      uint16_t ord = s->getOrdinal();
      HintNameChunk *hintChunk = nullptr;
      Chunk *lookupsChunk, *addressesChunk;

      if (s->getExternalName().empty()) {
        lookupsChunk = make<OrdinalOnlyChunk>(ctx, ord);
        addressesChunk = make<OrdinalOnlyChunk>(ctx, ord);
      } else {
        hintChunk = make<HintNameChunk>(s->getExternalName(), ord);
        lookupsChunk = make<LookupChunk>(ctx, hintChunk);
        addressesChunk = make<LookupChunk>(ctx, hintChunk);
        hints.push_back(hintChunk);
      }

      if (ctx.hybridTarget && !lookupsTerminator && s->file->isEC() &&
          !s->file->hybridFile) {
        lookupsTerminator = lookupsChunk;
        addressesTerminator = addressesChunk;
        lookupsChunk = make<NullChunk>(ctx.config.wordsize);
        addressesChunk = make<NullChunk>(ctx.config.wordsize);

        ctx.addArm64XReloc(IMAGE_DVRT_ARM64X_FIXUP_TYPE_VALUE, nullptr,
                           lookupsChunk, 0, nullptr, hintChunk,
                           hintChunk ? 0 : ord, sizeof(uint64_t));
        ctx.addArm64XReloc(IMAGE_DVRT_ARM64X_FIXUP_TYPE_VALUE, nullptr,
                           addressesChunk, 0, nullptr, hintChunk,
                           hintChunk ? 0 : ord, sizeof(uint64_t));
        ctx.addArm64XReloc(IMAGE_DVRT_ARM64X_FIXUP_TYPE_ZEROFILL, nullptr,
                           lookupsTerminator, 0, nullptr, nullptr, 0,
                           sizeof(uint64_t));
        ctx.addArm64XReloc(IMAGE_DVRT_ARM64X_FIXUP_TYPE_ZEROFILL, nullptr,
                           addressesTerminator, 0, nullptr, nullptr, 0,
                           sizeof(uint64_t));
      }

      lookups.push_back(lookupsChunk);
      addresses.push_back(addressesChunk);

      if (s->file->impECSym) {
        Chunk *impchkChunk = s->file->impchkThunk;
        auto chunk = make<AuxImportChunk>(ctx, impchkChunk);
        auxIat.push_back(chunk);
        s->file->impECSym->setLocation(chunk);

        chunk = make<AuxImportChunk>(ctx, impchkChunk);
        auxIatCopy.push_back(chunk);
        s->file->auxImpCopySym->setLocation(chunk);
      } else if (ctx.config.machine == ARM64X) {
        auxIat.push_back(make<NullChunk>(ctx.config.wordsize));
        auxIatCopy.push_back(make<NullChunk>(ctx.config.wordsize));
      }
    }
    // Terminate with null values.
    lookups.push_back(lookupsTerminator ? lookupsTerminator
                                        : make<NullChunk>(ctx.config.wordsize));
    addresses.push_back(addressesTerminator
                            ? addressesTerminator
                            : make<NullChunk>(ctx.config.wordsize));
    if (isArm64EC(ctx.config.machine)) {
      auxIat.push_back(make<NullChunk>(ctx.config.wordsize));
      auxIatCopy.push_back(make<NullChunk>(ctx.config.wordsize));
    }

    for (int i = 0, e = syms.size(); i < e; ++i) {
      syms[i]->setLocation(addresses[base + i]);
      if (syms[i]->file->hybridFile)
        syms[i]->file->hybridFile->impSym->setLocation(addresses[base + i]);
    }

    // Create the import table header.
    dllNames.push_back(make<StringChunk>(syms[0]->getDLLName()));
    auto *dir = make<ImportDirectoryChunk>(dllNames.back());
    dir->lookupTab = lookups[base];
    dir->addressTab = addresses[base];
    dirs.push_back(dir);

    if (ctx.hybridTarget) {
      uint32_t nativeOnly = 0;
      for (DefinedImportData *s : syms) {
        if (s->file->isEC())
          break;
        ++nativeOnly;
      }
      if (nativeOnly) {
        ctx.addArm64XReloc(
            IMAGE_DVRT_ARM64X_FIXUP_TYPE_DELTA, nullptr, dir,
            offsetof(ImportDirectoryTableEntry, ImportLookupTableRVA), nullptr,
            nullptr, nativeOnly * sizeof(uint64_t), 0);
        ctx.addArm64XReloc(
            IMAGE_DVRT_ARM64X_FIXUP_TYPE_DELTA, nullptr, dir,
            offsetof(ImportDirectoryTableEntry, ImportAddressTableRVA), nullptr,
            nullptr, nativeOnly * sizeof(uint64_t), 0);
      }
    }
  }
  // Add null terminator.
  dirs.push_back(make<NullChunk>(sizeof(ImportDirectoryTableEntry)));
}

std::vector<Chunk *> DelayLoadContents::getChunks() {
  std::vector<Chunk *> v;
  v.insert(v.end(), dirs.begin(), dirs.end());
  v.insert(v.end(), names.begin(), names.end());
  v.insert(v.end(), hintNames.begin(), hintNames.end());
  v.insert(v.end(), dllNames.begin(), dllNames.end());
  return v;
}

std::vector<Chunk *> DelayLoadContents::getDataChunks() {
  std::vector<Chunk *> v;
  v.insert(v.end(), moduleHandles.begin(), moduleHandles.end());
  v.insert(v.end(), addresses.begin(), addresses.end());
  v.insert(v.end(), auxIat.begin(), auxIat.end());
  return v;
}

uint64_t DelayLoadContents::getDirSize() {
  return dirs.size() * sizeof(delay_import_directory_table_entry);
}

void DelayLoadContents::create() {
  std::vector<std::vector<DefinedImportData *>> v =
      binImports(ctx, imports, false);

  Chunk *unwind = newTailMergeUnwindInfoChunk(ctx.primaryTarget);

  // Create .didat contents for each DLL.
  for (std::vector<DefinedImportData *> &syms : v) {
    // Create the delay import table header.
    dllNames.push_back(make<StringChunk>(syms[0]->getDLLName()));
    auto *dir = make<DelayDirectoryChunk>(dllNames.back());
    Chunk *tmEC = nullptr;

    size_t base = addresses.size();
    ctx.forEachTarget([&](COFFTargetContext &target) {
      Chunk *tm = newTailMergeChunk(target, dir);
      Chunk *pdataChunk =
          unwind ? newTailMergePDataChunk(target, tm, unwind) : nullptr;
      size_t targetBase = addresses.size();
      if (target.machine == ARM64EC)
        tmEC = make<DelayHelperChunkARM64EC>(
            dir, cast<Defined>(target.delayLoadHelper));

      for (DefinedImportData *s : syms) {
        if (s->file->isEC() != isArm64EC(target.machine))
          continue;
        Chunk *t = newThunkChunk(target, s, tm);
        auto *a = make<DelayAddressChunk>(target.ctx, t);
        addresses.push_back(a);
        s->setLocation(a);
        thunks.push_back(t);
        StringRef extName = s->getExternalName();
        if (extName.empty()) {
          names.push_back(make<OrdinalOnlyChunk>(target.ctx, s->getOrdinal()));
        } else {
          auto *c = make<HintNameChunk>(extName, 0);
          names.push_back(make<LookupChunk>(target.ctx, c));
          hintNames.push_back(c);
          // Add a synthetic symbol for this load thunk, using the
          // "__imp___load" prefix, in case this thunk needs to be added to the
          // list of valid call targets for Control Flow Guard.
          StringRef symName = saver().save("__imp___load_" + extName);
          s->loadThunkSym =
              cast<DefinedSynthetic>(target.symtab.addSynthetic(symName, t));
        }

        if (s->file->impECSym) {
          auto thunkEC = make<ThunkChunkARM64EC>(s->file, tmEC);
          thunks.push_back(thunkEC);
          auto chunk = make<AuxImportChunk>(target.ctx, thunkEC);
          auxIat.push_back(chunk);
          s->file->impECSym->setLocation(chunk);
        }
      }
      thunks.push_back(tm);
      if (tmEC)
        thunks.push_back(tmEC);
      if (pdataChunk)
        pdata.push_back(pdataChunk);
      StringRef tmName =
          saver().save("__tailMerge_" + syms[0]->getDLLName().lower());
      target.symtab.addSynthetic(tmName, tm);
      // Terminate with null values.
      addresses.push_back(make<NullChunk>(8));
      names.push_back(make<NullChunk>(8));
      if (target.machine == ARM64EC) {
        auxIat.push_back(make<NullChunk>(8));
        if (ctx.hybridTarget) {
          ctx.addArm64XReloc(IMAGE_DVRT_ARM64X_FIXUP_TYPE_DELTA, nullptr, dir,
                             offsetof(delay_import_directory_table_entry,
                                      DelayImportAddressTable),
                             nullptr, nullptr,
                             (targetBase - base) * sizeof(uint64_t), 0);
          ctx.addArm64XReloc(IMAGE_DVRT_ARM64X_FIXUP_TYPE_DELTA, nullptr, dir,
                             offsetof(delay_import_directory_table_entry,
                                      DelayImportNameTable),
                             nullptr, nullptr,
                             (targetBase - base) * sizeof(uint64_t), 0);
        }
      }
    });

    auto *mh = make<NullChunk>(8);
    mh->setAlignment(8);
    moduleHandles.push_back(mh);

    // Fill the delay import table header fields.
    dir->moduleHandle = mh;
    dir->addressTab = addresses[base];
    dir->nameTab = names[base];
    dirs.push_back(dir);
  }

  if (unwind)
    unwindinfo.push_back(unwind);
  // Add null terminator.
  dirs.push_back(make<NullChunk>(sizeof(delay_import_directory_table_entry)));
}

Chunk *DelayLoadContents::newTailMergeChunk(COFFTargetContext &target,
                                            Chunk *dir) {
  auto helper = cast<Defined>(target.delayLoadHelper);
  switch (target.machine) {
  case AMD64:
  case ARM64EC:
    return make<TailMergeChunkX64>(dir, helper);
  case I386:
    return make<TailMergeChunkX86>(target.ctx, dir, helper);
  case ARMNT:
    return make<TailMergeChunkARM>(target.ctx, dir, helper);
  case ARM64:
    return make<TailMergeChunkARM64>(dir, helper);
  default:
    llvm_unreachable("unsupported machine type");
  }
}

Chunk *
DelayLoadContents::newTailMergeUnwindInfoChunk(COFFTargetContext &target) {
  switch (target.ctx.config.machine) {
  case AMD64:
    return make<TailMergeUnwindInfoX64>();
    // FIXME: Add support for other architectures.
  default:
    return nullptr; // Just don't generate unwind info.
  }
}
Chunk *DelayLoadContents::newTailMergePDataChunk(COFFTargetContext &target,
                                                 Chunk *tm, Chunk *unwind) {
  switch (target.machine) {
  case AMD64:
    return make<TailMergePDataChunkX64>(tm, unwind);
    // FIXME: Add support for other architectures.
  default:
    return nullptr; // Just don't generate unwind info.
  }
}

Chunk *DelayLoadContents::newThunkChunk(COFFTargetContext &target,
                                        DefinedImportData *s,
                                        Chunk *tailMerge) {
  switch (target.machine) {
  case AMD64:
  case ARM64EC:
    return make<ThunkChunkX64>(s, tailMerge);
  case I386:
    return make<ThunkChunkX86>(target.ctx, s, tailMerge);
  case ARMNT:
    return make<ThunkChunkARM>(target.ctx, s, tailMerge);
  case ARM64:
    return make<ThunkChunkARM64>(s, tailMerge);
  default:
    llvm_unreachable("unsupported machine type");
  }
}

void EdataContents::create(COFFTargetContext &target) {
  unsigned baseOrdinal = 1 << 16, maxOrdinal = 0;
  for (Export &e : target.exports) {
    baseOrdinal = std::min(baseOrdinal, (unsigned)e.ordinal);
    maxOrdinal = std::max(maxOrdinal, (unsigned)e.ordinal);
  }
  // Ordinals must start at 1 as suggested in:
  // https://learn.microsoft.com/en-us/cpp/build/reference/export-exports-a-function?view=msvc-170
  assert(baseOrdinal >= 1);

  auto *dllName =
      make<StringChunk>(sys::path::filename(target.ctx.config.outputFile));
  auto *addressTab = make<AddressTableChunk>(target, baseOrdinal, maxOrdinal);
  std::vector<Chunk *> names;
  for (Export &e : target.exports)
    if (!e.noname)
      names.push_back(make<StringChunk>(e.exportName));

  std::vector<Chunk *> forwards;
  for (Export &e : target.exports) {
    if (e.forwardTo.empty())
      continue;
    e.forwardChunk = make<StringChunk>(e.forwardTo);
    forwards.push_back(e.forwardChunk);
  }

  auto *nameTab = make<NamePointersChunk>(names);
  auto *ordinalTab =
      make<ExportOrdinalChunk>(target, baseOrdinal, names.size());
  auto *dir =
      make<ExportDirectoryChunk>(baseOrdinal, maxOrdinal, names.size(), dllName,
                                 addressTab, nameTab, ordinalTab);
  chunks.push_back(dir);
  chunks.push_back(dllName);
  chunks.push_back(addressTab);
  chunks.push_back(nameTab);
  chunks.push_back(ordinalTab);
  chunks.insert(chunks.end(), names.begin(), names.end());
  chunks.insert(chunks.end(), forwards.begin(), forwards.end());
}

} // namespace lld::coff
