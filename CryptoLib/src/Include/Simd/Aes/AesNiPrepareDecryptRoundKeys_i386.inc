// AES-NI decrypt-schedule preparation (i386).
// Runs aesimc on the middle round keys (rounds 1..N_R - 1) in place and then
// reverses the order of the N_R + 1 round keys to produce a schedule suitable
// for aesdec / aesdeclast during decrypt.
//
// Entry (after SimdProc2Begin_i386): ebx = round keys
// (16 * (N_R + 1) bytes, in place), esi = FNRounds in {10, 12, 14}.
// Pushes/pops edi; remaps internally to ecx = keys, ebx = nrounds.
// Uses esi / edi / eax as loop counters and scratch, xmm0..xmm2 for aesimc /
// swap.
// AES-NI instructions are db-encoded for broad assembler compatibility.
//
  push edi
  mov ecx, ebx
  mov ebx, esi
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
