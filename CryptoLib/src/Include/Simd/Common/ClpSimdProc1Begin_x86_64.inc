// Shared SIMD/asm procedure prologue (1 parameter, x86-64).
// After inclusion: rcx = param1 (MS x64 ABI).
// When CRYPTOLIB_SYSV_X64_ABI is defined, remaps rdi -> rcx.
// Usage:
//   procedure MyProc(P1: Pointer);
//     {$I ..\..\Include\Simd\Common\ClpSimdProc1Begin_x86_64.inc}
//     // ... instructions using rcx ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
{$ENDIF}
asm
{$IFNDEF FPC}
  .noframe
{$ENDIF}
{$IFDEF CRYPTOLIB_SYSV_X64_ABI}
  mov rcx, rdi
{$ENDIF}
