// Shared SIMD/asm procedure prologue (4 parameters, AArch64).
// After inclusion: x0 = param1, x1 = param2, x2 = param3, x3 = param4
//   (AAPCS64; no remapping needed, unlike the x86 SysV/MS variants).
// Usage:
//   procedure MyProc(P1, P2, P3: Pointer; P4: Int32);
//     {$I ..\..\Include\Simd\Common\ClpSimdProc4Begin_aarch64.inc}
//     // ... instructions using x0, x1, x2, x3 (w3 for 32-bit param4) ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
{$ENDIF}
asm
