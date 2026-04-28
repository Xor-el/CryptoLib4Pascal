// Shared SIMD procedure prologue for 5-parameter assembly functions (i386).
// After inclusion: ebx = param1, esi = param2, edi = param3, eax = param4, ecx = param5
//   (i386 register convention).
// FPC: param4 and param5 are at [esp+20] and [esp+16] after push EBX/ESI/EDI (see asm).
// Delphi Win32: param4 at dword ptr [ebp + 12], param5 at dword ptr [ebp + 8].
// Callee-saved EBX, ESI, EDI — epilogue must pop EDI, ESI, EBX.
// Usage:
//   procedure MyProc(P1, P2: Pointer; P3, P4: Int32; P5: Pointer);
//     {$I ..\..\Include\Simd\Common\SimdProc5Begin_i386.inc}
//     // ... SIMD instructions using ebx, esi, edi, eax, ecx ...
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
  mov eax, dword ptr [esp + 20] // param4
  mov ecx, dword ptr [esp + 16] // param5
{$ELSE}
asm
  {$IFDEF MSWINDOWS}
  push ebx
  push esi
  push edi
  mov ebx, eax
  mov esi, edx
  mov edi, ecx
  mov eax, dword ptr [ebp + 12] // param4 (first stack param = high address)
  mov ecx, dword ptr [ebp + 8]  // param5 (last stack param)
  {$ELSE}
  push ebx
  push esi
  push edi
  mov ebx, dword ptr [ebp + 8]
  mov esi, dword ptr [ebp + 12]
  mov edi, dword ptr [ebp + 16]
  mov eax, dword ptr [ebp + 20]
  mov ecx, dword ptr [ebp + 24]
  {$ENDIF}
{$ENDIF}
