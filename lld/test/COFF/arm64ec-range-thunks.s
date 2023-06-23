// REQUIRES: aarch64

// RUN: llvm-mc -filetype=obj -triple=arm64ec-windows %s -o %t.obj
// RUN: llvm-mc -filetype=obj -triple=arm64ec-windows %S/Inputs/loadconfig-arm64ec.s -o %t-loadcfg.obj

// RUN: lld-link -machine:arm64ec -entry:main -subsystem:console %t.obj %t-loadcfg.obj -out:%t.exe -map \
// RUN:          -verbose 2>&1 | FileCheck -check-prefix=VERBOSE %s
// RUN: llvm-objdump --no-print-imm-hex -d %t.exe | FileCheck --check-prefix=DISASM %s
// RUN: llvm-readobj --coff-load-config %t.exe | FileCheck --check-prefix=LOADCFG %s

// VERBOSE: Added 3 thunks with margin {{.*}} in 1 passes

    .globl main
    .globl func1
    .globl func2
    .text
main:
    tbz w0, #0, func1
    ret
    .section .text$a, "xr"
    .space 0x8000
    .section .text$b, "xr"
func1:
    tbz w0, #0, func2
    ret
    .space 1
    .section .text$c, "xr"
    .space 0x8000
    .section .text$d, "xr"
    .align 2
func2:
    tbz w0, #0, main
    ret


// DISASM:      Disassembly of section .text:
// DISASM-EMPTY:
// DISASM-NEXT: 0000000140001000 <.text>:
// DISASM-NEXT: 140001000: 36000040     tbz     w0, #0, 0x140001008 <.text+0x8>
// DISASM-NEXT: 140001004: d65f03c0     ret
// DISASM-NEXT: 140001008: 90000050     adrp    x16, 0x140009000 <.text+0x8000>
// DISASM-NEXT: 14000100c: 91005210     add     x16, x16, #20
// DISASM-NEXT: 140001010: d61f0200     br      x16
// DISASM-NEXT:                 ...
// DISASM-NEXT: 140009014: 36000060     tbz     w0, #0, 0x140009020 <.text+0x8020>
// DISASM-NEXT: 140009018: d65f03c0     ret
// DISASM-NEXT: 14000901c: 00000000     udf     #0
// DISASM-NEXT: 140009020: 90000050     adrp    x16, 0x140011000 <.text+0x10000>
// DISASM-NEXT: 140009024: 9100b210     add     x16, x16, #44
// DISASM-NEXT: 140009028: d61f0200     br      x16
// DISASM-NEXT:                 ...
// DISASM-NEXT: 14001102c: 36000040     tbz     w0, #0, 0x140011034 <.text+0x10034>
// DISASM-NEXT: 140011030: d65f03c0     ret
// DISASM-NEXT: 140011034: 90ffff90     adrp    x16, 0x140001000 <.text>
// DISASM-NEXT: 140011038: 91000210     add     x16, x16, #0
// DISASM-NEXT: 14001103c: d61f0200     br      x16
// DISASM-EMPTY:
// DISASM-NEXT: Disassembly of section .hexpthk:
// DISASM-EMPTY:
// DISASM-NEXT: 0000000140012000 <.hexpthk>:
// DISASM-NEXT: 140012000: 48 8b c4                     movq    %rsp, %rax
// DISASM-NEXT: 140012003: 48 89 58 20                  movq    %rbx, 32(%rax)
// DISASM-NEXT: 140012007: 55                           pushq   %rbp
// DISASM-NEXT: 140012008: 5d                           popq    %rbp
// DISASM-NEXT: 140012009: e9 f2 ef fe ff               jmp     0x140001000 <.text>
// DISASM-NEXT: 14001200e: cc                           int3
// DISASM-NEXT: 14001200f: cc                           int3

// LOADCFG:       CodeMap [
// LOADCFG-NEXT:    0x1000 - 0x11040  ARM64EC
// LOADCFG-NEXT:    0x12000 - 0x12010  X64
// LOADCFG-NEXT:  ]
// LOADCFG-NEXT:  CodeRangesToEntryPoints [
// LOADCFG-NEXT:    0x12000 - 0x12010 -> 0x12000
// LOADCFG-NEXT:  ]
// LOADCFG-NEXT:  RedirectionMetadata [
// LOADCFG-NEXT:    0x12000 -> 0x1000
// LOADCFG-NEXT:  ]
