// Shared SIMD/asm procedure prologue (1 parameter, x86-64).
// After inclusion: rcx = param1 (MS x64 ABI).
// On FPC non-Windows (System V AMD64), remaps rdi -> rcx.
// Usage:
//   procedure MyProc(P1: Pointer);
//     {$I ..\..\Include\Simd\Common\SimdProc1Begin_x86_64.inc}
//     // ... instructions using rcx ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
asm
  {$IFNDEF MSWINDOWS}
  mov rcx, rdi
  {$ENDIF}
{$ELSE}
asm
  .noframe
{$ENDIF}
