// XGETBV query helper, ECX = 0 (i386 + x86-64).
// Issues `xgetbv` with ECX = 0 (reads XCR0) and writes the returned
// EAX:EDX 64-bit value to the UInt64 at the supplied pointer.
//
// Entry contract (register convention varies by ABI):
//   i386:             eax = @AResult.
//   x86-64 MS ABI:    rcx = @AResult (remapped internally to r8).
//   x86-64 FPC Unix:  rdi = @AResult (remapped internally to r8).
// Preserves ebx on i386. XGETBV is db-encoded for broad assembler
// compatibility.
{$IFDEF FPC}
  assembler; nostackframe;
{$ENDIF}
asm
{$IFDEF CRYPTOLIB_I386_ASM}
  push ebx
  mov ebx, eax
  xor ecx, ecx
  db $0F, $01, $D0 // xgetbv
  mov [ebx], eax
  mov [ebx + 4], edx
  pop ebx
{$ELSE}
  {$IFDEF FPC}
  {$IFDEF MSWINDOWS}
  mov r8, rcx
  {$ELSE}
  mov r8, rdi
  {$ENDIF}
  xor ecx, ecx
  db $0F, $01, $D0 // xgetbv
  mov dword ptr [r8], eax
  mov dword ptr [r8 + 4], edx
  {$ELSE}
  .noframe
  mov r8, rcx
  xor ecx, ecx
  db $0F, $01, $D0 // xgetbv
  mov dword ptr [r8], eax
  mov dword ptr [r8 + 4], edx
  {$ENDIF}
{$ENDIF}
