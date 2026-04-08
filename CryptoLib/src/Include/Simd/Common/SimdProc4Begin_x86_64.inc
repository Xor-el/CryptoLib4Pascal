// Shared SIMD/asm procedure prologue (4 parameters, x86-64).
// After inclusion: rcx = param1, rdx = param2, r8 = param3, r9 = param4 (MS x64 ABI).
// On FPC non-Windows, remaps rdi, rsi, rdx, rcx -> rcx, rdx, r8, r9.
// Usage:
//   procedure MyProc(P1, P2, P3, P4: Pointer);
//     {$I ..\..\Include\Simd\Common\SimdProc4Begin_x86_64.inc}
//     // ... instructions using rcx, rdx, r8, r9 ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
asm
  {$IFNDEF MSWINDOWS}
  mov r9, rcx
  mov r8, rdx
  mov rdx, rsi
  mov rcx, rdi
  {$ENDIF}
{$ELSE}
asm
  .noframe
{$ENDIF}
