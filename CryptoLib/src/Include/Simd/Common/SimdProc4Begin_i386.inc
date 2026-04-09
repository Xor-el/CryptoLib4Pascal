// Shared SIMD/asm procedure prologue (4 parameters, i386).
// After inclusion: ebx = param1, esi = param2, edi = param3, eax = param4 (loaded from [esp+16]).
// Stack after pushes: [esp]=edi_sav, [esp+4]=esi_sav, [esp+8]=ebx_sav, [esp+12]=ret, [esp+16]=param4.
// Fourth parameter is on the stack (Register convention: first three in EAX, EDX, ECX).
// Epilogue in your body: pop edi; pop esi; pop ebx; (then implicit ret).
// Usage:
//   procedure MyProc(P1, P2, P3, P4: Pointer);
//     {$I ..\..\Include\Simd\Common\SimdProc4Begin_i386.inc}
//     // ... use ebx, esi, edi, eax ...
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
  mov eax, [esp + 16]
{$ELSE}
asm
  push ebx
  push esi
  push edi
  mov ebx, eax
  mov esi, edx
  mov edi, ecx
  mov eax, [esp + 16]
{$ENDIF}
