// CPUID: leaf in eax, subleaf in edx, TCpuIdResult pointer in ecx (i386 register convention).
// Preserves ebx; esi holds the result pointer while CPUID runs.
// x86-64: MS ABI ecx=leaf, edx=subleaf, r8=result; preserves rbx. FPC Unix: rdi, rsi, rdx remapped.
{$IFDEF FPC}
  assembler; nostackframe;
{$ENDIF}
asm
{$IFDEF CRYPTOLIB_I386_ASM}
  push ebx
  push esi
  mov esi, ecx
  mov ecx, edx
  cpuid
  mov [esi], eax
  mov [esi + 4], ebx
  mov [esi + 8], ecx
  mov [esi + 12], edx
  pop esi
  pop ebx
{$ELSE}
  {$IFDEF FPC}
  push rbx
  {$IFDEF MSWINDOWS}
  mov eax, ecx
  mov ecx, edx
  cpuid
  mov dword ptr [r8], eax
  mov dword ptr [r8 + 4], ebx
  mov dword ptr [r8 + 8], ecx
  mov dword ptr [r8 + 12], edx
  {$ELSE}
  mov eax, edi
  mov ecx, esi
  mov r8, rdx
  cpuid
  mov dword ptr [r8], eax
  mov dword ptr [r8 + 4], ebx
  mov dword ptr [r8 + 8], ecx
  mov dword ptr [r8 + 12], edx
  {$ENDIF}
  pop rbx
  {$ELSE}
  .PUSHNV RBX
  mov eax, ecx
  mov ecx, edx
  cpuid
  mov dword ptr [r8], eax
  mov dword ptr [r8 + 4], ebx
  mov dword ptr [r8 + 8], ecx
  mov dword ptr [r8 + 12], edx
  {$ENDIF}
{$ENDIF}
