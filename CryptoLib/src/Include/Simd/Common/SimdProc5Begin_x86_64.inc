// Shared SIMD/asm procedure prologue (5 parameters, x86-64).
// After inclusion: rcx = param1, rdx = param2, r8 = param3, r9 = param4, r10 = param5 (MS x64 ABI).
// On FPC non-Windows, remaps rdi, rsi, rdx, rcx, r8 -> rcx, rdx, r8, r9, r10.
// On MS x64, 5th argument is at [rsp+40] after the call (shadow space + return address).
// Usage:
//   procedure MyProc(P1, P2: Pointer; P3, P4: Int32; P5: Pointer);
//     {$I ..\..\Include\Simd\Common\SimdProc5Begin_x86_64.inc}
//     // ... instructions using rcx, rdx, r8, r9, r10 ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
asm
  {$IFNDEF MSWINDOWS}
  mov r10, r8
  mov r9, rcx
  mov r8, rdx
  mov rdx, rsi
  mov rcx, rdi
  {$ELSE}
  mov r10, [rsp + 40]
  {$ENDIF}
{$ELSE}
asm
  .noframe
  mov r10, [rsp + 40]
{$ENDIF}
