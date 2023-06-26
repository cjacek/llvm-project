// REQUIRES: aarch64
// RUN: llvm-mc -filetype=obj -triple=arm64ec-windows %s -o %t.obj
// RUN: lld-link -machine:arm64ec -dll -noentry %t.obj -out:%t.dll

// RUN: llvm-readobj --coff-basereloc %t.dll | FileCheck -check-prefix=RELOCS %s
// RELOCS:       Entry {
// RELOCS-NEXT:    Type: DIR64
// RELOCS-NEXT:    Address: 0x2000
// RELOCS-NEXT:  }

// RUN: llvm-readobj --hex-dump=.test %t.dll | FileCheck -check-prefix=TEST %s
// TEST: 0x180003000 00200000

// RUN: llvm-readobj --hex-dump=.rdata %t.dll | FileCheck -check-prefix=RDATA %s
// RDATA: 0x180002000 00100080 01000000

    .text
    .globl myfunc
myfunc:
    ret

    .section .test, "r"
    .rva __imp_myfunc
