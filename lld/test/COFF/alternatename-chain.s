// REQUIRES: x86

// Check that we may chain alternate names.
// RUN: llvm-mc -filetype=obj -triple=x86_64-windows %s -o %t.obj
// RUN: lld-link -dll -noentry %t.obj -alternatename:sym=a -alternatename:a=def
// RUN: lld-link -dll -noentry %t.obj -alternatename:sym=z -alternatename:z=def

        .data
        .rva sym

        .globl def
def:
        .word 1
