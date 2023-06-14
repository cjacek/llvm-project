// ARM64EC code is always instrumented, check that CF_INSTRUMENTED flag is set even with -guard:no argument.

// REQUIRES: aarch64

// RUN: llvm-mc -filetype=obj -triple=arm64ec-windows %s -o %t.obj
// RUN: llvm-mc -filetype=obj -triple=arm64ec-windows %S/Inputs/loadconfig-arm64ec.s -o %t-loadconfig.obj

// RUN: lld-link -out:%t1.dll -machine:arm64ec %t.obj %t-loadconfig.obj -dll -noentry
// RUN: lld-link -out:%t2.dll -machine:arm64ec %t.obj %t-loadconfig.obj -dll -noentry -guard:no

// RUN: llvm-readobj --coff-load-config %t1.dll | FileCheck %s
// RUN: llvm-readobj --coff-load-config %t2.dll | FileCheck %s
// CHECK:       GuardFlags [ (0x100)
// CHECK-NEXT:    CF_INSTRUMENTED (0x100)
// CHECK-NEXT:  ]

// RUN: llvm-readobj --hex-dump=.test %t1.dll | FileCheck --check-prefix=SYM %s
// RUN: llvm-readobj --hex-dump=.test %t2.dll | FileCheck --check-prefix=SYM %s
// SYM: 0x180003000 00010000

        .section .test, "r"
        .word __guard_flags
