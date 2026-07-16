// Shared SIMD/asm procedure prologue (5 parameters, AArch64).
// After inclusion: x0 = param1, x1 = param2, x2 = param3, x3 = param4,
//   x4 = param5 (AAPCS64; no remapping and no stack loads needed, unlike
//   the x86 SysV/MS variants).
// Usage:
//   procedure MyProc(P1, P2: Pointer; P3, P4: Int32; P5: Pointer);
//     {$I ..\..\Include\Simd\Common\ClpSimdProc5Begin_aarch64.inc}
//     // ... instructions using x0..x4 (wN for 32-bit params) ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
{$ENDIF}
asm
