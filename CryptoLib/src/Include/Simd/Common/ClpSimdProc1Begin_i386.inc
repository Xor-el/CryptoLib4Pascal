// Shared SIMD procedure prologue for 1-parameter assembly functions (i386).
// After inclusion: ebx = param1 (EAX at entry; callee saves EBX).
// FPC and Delphi Win32 share the same i386 register convention here.
// Bodies must end with: pop ebx before the Pascal 'end' (which emits ret).
// Usage:
//   procedure MyProc(P1: Pointer);
//     {$I ..\..\Include\Simd\Common\ClpSimdProc1Begin_i386.inc}
//     // ... SIMD instructions using ebx ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
{$ENDIF}
asm
  push ebx
  mov ebx, eax
