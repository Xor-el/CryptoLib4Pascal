// Shared SIMD/asm procedure prologue (1 parameter, AArch64).
// After inclusion: x0 = param1 (AAPCS64; no remapping needed).
// Usage:
//   procedure MyProc(P1: Pointer);
//     {$I ..\..\Include\Simd\Common\ClpSimdProc1Begin_aarch64.inc}
//     // ... instructions using x0 ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
{$ENDIF}
asm
