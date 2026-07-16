// Shared SIMD/asm procedure prologue (2 parameters, AArch64).
// After inclusion: x0 = param1, x1 = param2 (AAPCS64; no remapping needed).
// Usage:
//   procedure MyProc(P1, P2: Pointer);
//     {$I ..\..\Include\Simd\Common\ClpSimdProc2Begin_aarch64.inc}
//     // ... instructions using x0, x1 ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
{$ENDIF}
asm
