// REQUIRES: aarch64

// RUN: llvm-mc -filetype=obj -triple=arm64ec-windows %s -o %t.obj
// RUN: llvm-mc -filetype=obj -triple=arm64ec-windows %S/Inputs/arm64ec-loadcfg.s -o %t-loadcfg.obj
// RUN: lld-link -out:%t.dll -machine:arm64ec %t.obj %t-loadcfg.obj -dll -noentry

// RUN: llvm-objdump -d %t.dll | FileCheck %s
// CHECK:      0000000180001000 <.text>:
// CHECK-NEXT: 180001000: 52800040     mov     w0, #0x2                // =2
// CHECK-NEXT: 180001004: d65f03c0     ret
// CHECK-NEXT: 180001008: 52800060     mov     w0, #0x3                // =3
// CHECK-NEXT: 18000100c: d65f03c0     ret

        .text
        .globl arm64ec_func_sym
        .p2align 2, 0x0
arm64ec_func_sym:
        mov w0, #2
        ret

        .section .wowthk$aa, "x"
        .globl wowthk_sym
        .p2align 3, 0x0
wowthk_sym:
        mov w0, #3
        ret
