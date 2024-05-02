; RUN: llc -mtriple=arm64ec-pc-windows-msvc < %s | FileCheck %s

define dso_local i32 @func() hybrid_patchable nounwind {
; CHECK-LABEL:     .def    "#func$hp_target";
; CHECK:           .section        .text,"xr",discard,"#func$hp_target"
; CHECK-NEXT:      .globl  "#func$hp_target"               // -- Begin function #func$hp_target
; CHECK-NEXT:      .p2align        2
; CHECK-NEXT:  "#func$hp_target":                      // @"#func$hp_target"
; CHECK-NEXT:      // %bb.0:
; CHECK-NEXT:      mov     w0, #1                          // =0x1
; CHECK-NEXT:      ret
  ret i32 1
}

define internal i32 @static_func() hybrid_patchable nounwind {
; CHECK-LABEL:     .def    static_func;
; CHECK:       static_func:                            // @static_func
; CHECK-NEXT:      // %bb.0:
; CHECK-NEXT:      mov     w0, #2                          // =0x2
; CHECK-NEXT:      ret
  ret i32 2
}

define dso_local void @caller() nounwind {
; CHECK-LABEL:     .def    "#caller";
; CHECK:           .section        .text,"xr",discard,"#caller"
; CHECK-NEXT:      .globl  "#caller"                       // -- Begin function #caller
; CHECK-NEXT:      .p2align        2
; CHECK-NEXT:  "#caller":                              // @"#caller"
; CHECK-NEXT:      .weak_anti_dep  caller
; CHECK-NEXT:  .set caller, "#caller"@WEAKREF
; CHECK-NEXT:  // %bb.0:
; CHECK-NEXT:      str     x30, [sp, #-16]!                // 8-byte Folded Spill
; CHECK-NEXT:      bl      "#func"
; CHECK-NEXT:      bl      static_func
; CHECK-NEXT:      ldr     x30, [sp], #16                  // 8-byte Folded Reload
; CHECK-NEXT:      ret
  %1 = call i32 @func()
  %2 = call i32 @static_func()
  ret void
}

; CHECK: .def    $ientry_thunk$cdecl$i8$v;
; CHECK: .def    $ientry_thunk$cdecl$v$v;
; CHECK: .def    $iexit_thunk$cdecl$i8$v;

; CHECK-LABEL:       def    "#func$hybpatch_thunk";
; CHECK:            .section        .wowthk$aa,"xr",discard,"#func$hybpatch_thunk"
; CHECK-NEXT:       .globl  "#func$hybpatch_thunk"          // -- Begin function #func$hybpatch_thunk
; CHECK-NEXT:       .p2align        2
; CHECK-NEXT:   "#func$hybpatch_thunk":                 // @"#func$hybpatch_thunk"
; CHECK-NEXT:       .weak  func
; CHECK-NEXT:   .set func, "EXP+#func"@WEAKREF
; CHECK-NEXT:       .weak  "#func"
; CHECK-NEXT:   .set "#func", "#func$hybpatch_thunk"@WEAKREF
; CHECK-NEXT:   .seh_proc "#func$hybpatch_thunk"
; CHECK-NEXT:   // %bb.0:
; CHECK-NEXT:       str     x30, [sp, #-16]!                // 8-byte Folded Spill
; CHECK-NEXT:       .seh_save_reg_x x30, 16
; CHECK-NEXT:       .seh_endprologue
; CHECK-NEXT:       adrp    x8, __os_arm64x_dispatch_call
; CHECK-NEXT:       adrp    x11, func
; CHECK-NEXT:       add     x11, x11, :lo12:func
; CHECK-NEXT:       ldr     x8, [x8, :lo12:__os_arm64x_dispatch_call]
; CHECK-NEXT:       adrp    x10, ($iexit_thunk$cdecl$i8$v)
; CHECK-NEXT:       add     x10, x10, :lo12:($iexit_thunk$cdecl$i8$v)
; CHECK-NEXT:       adrp    x9, "#func$hp_target"
; CHECK-NEXT:       add     x9, x9, :lo12:"#func$hp_target"
; CHECK-NEXT:       blr     x8
; CHECK-NEXT:       .seh_startepilogue
; CHECK-NEXT:       ldr     x30, [sp], #16                  // 8-byte Folded Reload
; CHECK-NEXT:       .seh_save_reg_x x30, 16
; CHECK-NEXT:       .seh_endepilogue
; CHECK-NEXT:       br      x11
; CHECK-NEXT:       .seh_endfunclet
; CHECK-NEXT:       .seh_endproc
