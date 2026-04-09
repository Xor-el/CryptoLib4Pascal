// Shared SIMD/asm procedure prologue (2 parameters, x86-64).
// After inclusion: rcx = param1, rdx = param2 (MS x64 ABI).
// On FPC non-Windows, remaps rdi, rsi -> rcx, rdx.
// Usage:
//   procedure MyProc(P1, P2: Pointer);
//     {$I ..\..\Include\Simd\Common\SimdProc2Begin_x86_64.inc}
//     // ... instructions using rcx, rdx ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
asm
  {$IFNDEF MSWINDOWS}
  mov rdx, rsi
  mov rcx, rdi
  {$ENDIF}
{$ELSE}
asm
  .noframe
{$ENDIF}
