// AES decrypt key schedule: aesimc middle rounds + reverse round-key order, i386.
// Expects: eax = round keys, edx = FNRounds (10, 12, or 14); register calling convention.
// Db-encoded AES-NI / SSE2 (broad assembler support).
//
  push ebx
  push esi
  push edi
  mov ecx, eax
  mov ebx, edx
  mov esi, 1
  mov edi, ebx
  dec edi
@aes_imc_loop:
  cmp esi, edi
  ja @aes_imc_done
  mov eax, esi
  shl eax, 4
  movdqu xmm0, [ecx + eax]
  movdqa xmm1, xmm0
  db $66, $0F, $38, $DB, $C1       // aesimc xmm0, xmm1
  movdqu [ecx + eax], xmm0
  inc esi
  jmp @aes_imc_loop
@aes_imc_done:
  xor esi, esi
  mov eax, ebx
@aes_swap_loop:
  cmp esi, eax
  jge @aes_swap_done
  mov edx, esi
  shl edx, 4
  mov edi, eax
  shl edi, 4
  movdqu xmm0, [ecx + edx]
  movdqu xmm1, [ecx + edi]
  movdqu [ecx + edx], xmm1
  movdqu [ecx + edi], xmm0
  inc esi
  dec eax
  jmp @aes_swap_loop
@aes_swap_done:
  pop edi
  pop esi
  pop ebx
