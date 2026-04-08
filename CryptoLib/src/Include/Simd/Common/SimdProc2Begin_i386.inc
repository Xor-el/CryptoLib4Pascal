// Shared SIMD/asm procedure prologue (2 parameters, i386).
// After inclusion: eax = param1, edx = param2 (register calling convention).
// FPC: Windows and Unix i386 use the same parameter entry layout.
// Usage:
//   procedure MyProc(P1, P2: Pointer);
//     {$I ..\..\Include\Simd\Common\SimdProc2Begin_i386.inc}
//     // ... instructions ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
{$ENDIF}
asm
