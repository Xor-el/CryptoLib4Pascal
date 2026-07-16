// Shared SIMD/asm procedure prologue (3 parameters, AArch64).
// After inclusion: x0 = param1, x1 = param2, x2 = param3 (AAPCS64; no
//   remapping needed, unlike the x86 SysV/MS variants).
// Usage:
//   procedure MyProc(P1, P2, P3: Pointer);
//     {$I ..\..\Include\Simd\Common\ClpSimdProc3Begin_aarch64.inc}
//     // ... instructions using x0, x1, x2 ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
{$ENDIF}
asm
