// REQUIRES: aarch64

// RUN: llvm-mc -filetype=obj -triple=arm64ec-windows %s -o %t.obj
// RUN: llvm-mc -filetype=obj -triple=arm64ec-windows %S/Inputs/loadconfig-arm64ec.s -o %t-loadcfg.obj
// RUN: lld-link -machine:arm64ec -dll -noentry -out:%t.dll %t.obj %t-loadcfg.obj \
// RUN:          -export:testfunc -export:testfunc2
// RUN: llvm-objdump -d %t.dll | FileCheck -check-prefix=DISASM %s

// DISASM:      Disassembly of section .text:
// DISASM-EMPTY:
// DISASM-NEXT: 0000000180001000 <.text>:
// DISASM-NEXT: 180001000: 00000015     udf     #0x15
// DISASM-NEXT: 180001004: 52800020     mov     w0, #0x1                // =1
// DISASM-NEXT: 180001008: d65f03c0     ret
// DISASM-NEXT: 18000100c: 00000011     udf     #0x11
// DISASM-NEXT: 180001010: 52800040     mov     w0, #0x2                // =2
// DISASM-NEXT: 180001014: d65f03c0     ret
// DISASM-NEXT: 180001018: 52800140     mov     w0, #0xa                // =10
// DISASM-NEXT: 18000101c: d65f03c0     ret
// DISASM-NEXT: 180001020: 52800280     mov     w0, #0x14               // =20
// DISASM-NEXT: 180001024: d65f03c0     ret
// DISASM-EMPTY:
// DISASM-NEXT: Disassembly of section .hexpthk:
// DISASM-EMPTY:
// DISASM-NEXT: 0000000180002000 <testfunc>:
// DISASM-NEXT: 180002000: 48 8b c4                     movq    %rsp, %rax
// DISASM-NEXT: 180002003: 48 89 58 20                  movq    %rbx, 0x20(%rax)
// DISASM-NEXT: 180002007: 55                           pushq   %rbp
// DISASM-NEXT: 180002008: 5d                           popq    %rbp
// DISASM-NEXT: 180002009: e9 f6 ef ff ff               jmp     0x180001004 <.text+0x4>
// DISASM-NEXT: 18000200e: cc                           int3
// DISASM-NEXT: 18000200f: cc                           int3
// DISASM-EMPTY:
// DISASM-NEXT: 0000000180002010 <testfunc2>:
// DISASM-NEXT: 180002010: 48 8b c4                     movq    %rsp, %rax
// DISASM-NEXT: 180002013: 48 89 58 20                  movq    %rbx, 0x20(%rax)
// DISASM-NEXT: 180002017: 55                           pushq   %rbp
// DISASM-NEXT: 180002018: 5d                           popq    %rbp
// DISASM-NEXT: 180002019: e9 f2 ef ff ff               jmp     0x180001010 <.text+0x10>
// DISASM-NEXT: 18000201e: cc                           int3
// DISASM-NEXT: 18000201f: cc                           int3

    .section .text,"xr",discard,testfunc
    .globl testfunc
    .p2align 2
testfunc:
    mov w0, #1
    ret

    .section .text,"xr",discard,testfunc2
    .globl testfunc2
    .p2align 2
testfunc2:
    mov w0, #2
    ret

    .section .wowthk$aa,"xr",discard,testthunk
    .globl testthunk
    .p2align 2
testthunk:
    mov w0, #10
    ret

    .section .wowthk$aa,"xr",discard,testthunk2
    .globl testthunk2
    .p2align 2
testthunk2:
    mov w0, #20
    ret

    .section .hybmp$x, "yi"
    .symidx testfunc
    .symidx testthunk
    .word 1
    .symidx testfunc2
    .symidx testthunk2
    .word 1
