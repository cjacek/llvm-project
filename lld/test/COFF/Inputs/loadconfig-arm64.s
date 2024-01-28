        .section .rdata,"dr"
        .globl _load_config_used
        .p2align 3, 0
_load_config_used:
        .word 0x140
        .fill 0x54, 1, 0
        .xword 0 // __security_cookie
        .fill 0x10, 1, 0
        .xword 0 // __guard_check_icall_fptr
        .xword 0 // __guard_dispatch_icall_fptr
        .xword __guard_fids_table
        .xword __guard_fids_count
        .xword __guard_flags
        .xword 0
        .xword __guard_iat_table
        .xword __guard_iat_count
        .xword __guard_longjmp_table
        .xword __guard_longjmp_count
        .xword 0
        .xword 0
        .fill 0x60, 1, 0
        .xword 0 // __castguard_check_failure_os_handled_fptr
        .xword 0

        /*
        .text
_guard_dispatch_icall_nop:
        br x9
        */

        /*
        .section ".00cfg","dr"
__guard_dispatch_icall_fptr:
        .xword 0 //_guard_dispatch_icall_nop
        */

        /*
__guard_check_icall_fptr:
        .xword 0
__guard_dispatch_icall_fptr:
        .xword 0
__castguard_check_failure_os_handled_fptr:
        .xword 0
__security_cookie:
        .xword 0
*/
