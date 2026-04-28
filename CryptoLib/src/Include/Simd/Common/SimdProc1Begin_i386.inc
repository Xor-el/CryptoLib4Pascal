// Shared SIMD procedure prologue for 1-parameter assembly functions (i386).
// After inclusion: ebx = param1 (EAX at entry; callee saves EBX).
// FPC: Windows and Unix i386 use the same single-parameter entry layout
// (first pointer-sized argument arrives in EAX under FPC's register calling
// convention for the default visibility of asm-only functions).
// Bodies must end with: pop ebx before the Pascal 'end' (which emits ret).
// Matches the idiom of SimdProc2Begin_i386.inc / SimdProc3Begin_i386.inc.
// Usage:
//   procedure MyProc(P1: Pointer);
//     {$I ..\..\Include\Simd\Common\SimdProc1Begin_i386.inc}
//     // ... SIMD instructions using ebx ...
//     // pop ebx     // the included kernel body emits this as its epilogue
//   end;
{$IFDEF FPC}
  assembler; nostackframe;
asm
  push ebx
  mov ebx, eax
{$ELSE}
asm
  push ebx
  mov ebx, eax
{$ENDIF}
