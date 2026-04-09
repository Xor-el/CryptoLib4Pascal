// Shared SIMD/asm procedure prologue (3 parameters, x86-64).
// After inclusion: rcx = param1, rdx = param2, r8 = param3 (MS x64 ABI).
// On FPC non-Windows, remaps rdi, rsi, rdx -> rcx, rdx, r8 (rdx saved before overwrite).
// Usage:
//   procedure MyProc(P1, P2, P3: Pointer);  // or mixed Pointer/Integer types
//     {$I ..\..\Include\Simd\Common\SimdProc3Begin_x86_64.inc}
//     // ... instructions using rcx, rdx, r8 ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
asm
  {$IFNDEF MSWINDOWS}
  mov r8, rdx
  mov rdx, rsi
  mov rcx, rdi
  {$ENDIF}
{$ELSE}
asm
  .noframe
{$ENDIF}
