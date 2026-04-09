// Shared SIMD/asm procedure prologue (3 parameters, i386).
// After inclusion: ebx = param1, esi = param2, edi = param3 (copied from EAX, EDX, ECX at entry).
// Copy params into callee-saved registers so EAX/EDX/ECX stay free for inner-loop temporaries.
// FPC: Windows and Unix i386 use the same parameter entry layout.
// Usage:
//   procedure MyProc(P1, P2: Pointer; N: Int32);
//     {$I ..\..\Include\Simd\Common\SimdProc3Begin_i386.inc}
//     // ... body using ebx, esi, edi ...
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
asm
  push ebx
  push esi
  push edi
  mov ebx, eax
  mov esi, edx
  mov edi, ecx
{$ELSE}
asm
  push ebx
  push esi
  push edi
  mov ebx, eax
  mov esi, edx
  mov edi, ecx
{$ENDIF}
