// CPUID query helper (i386 + x86-64).
// Issues `cpuid` with the caller-supplied leaf / subleaf and writes the
// returned eax, ebx, ecx, edx quad into a TCpuIdResult record at the
// supplied pointer.
//
// Entry contract (register convention varies by ABI):
//   i386:             eax = leaf, edx = subleaf, ecx = @TCpuIdResult.
//   x86-64 MS ABI:    ecx = leaf, edx = subleaf, r8 = @TCpuIdResult.
//   x86-64 FPC Unix:  rdi = leaf, rsi = subleaf, rdx = @TCpuIdResult
//                     (remapped internally to eax, ecx, r8).
// Preserves ebx / rbx around `cpuid` (required by all supported ABIs); on
// i386 also preserves esi (used to hold the result pointer during `cpuid`).
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
