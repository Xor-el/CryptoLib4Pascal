// Shared SIMD/asm procedure prologue (2 parameters, x86-64).
// After inclusion: rcx = param1, rdx = param2 (MS x64 ABI).
// When CRYPTOLIB_SYSV_X64_ABI is defined, remaps rdi, rsi -> rcx, rdx.
// Usage:
//   procedure MyProc(P1, P2: Pointer);
//     {$I ..\..\Include\Simd\Common\SimdProc2Begin_x86_64.inc}
//     // ... instructions using rcx, rdx ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
{$ENDIF}
asm
{$IFNDEF FPC}
  .noframe
{$ENDIF}
{$IFDEF CRYPTOLIB_SYSV_X64_ABI}
  mov rdx, rsi
  mov rcx, rdi
{$ENDIF}
