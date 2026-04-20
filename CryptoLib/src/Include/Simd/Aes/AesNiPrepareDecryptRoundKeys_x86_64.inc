// AES-NI decrypt-schedule preparation (x86-64).
// Runs aesimc on the middle round keys (rounds 1..N_R - 1) in place and then
// reverses the order of the N_R + 1 round keys to produce a schedule suitable
// for aesdec / aesdeclast during decrypt.
//
// Entry (MS x64 ABI / FPC remapped Unix): rcx = round keys
// (16 * (N_R + 1) bytes, in place), edx = FNRounds in {10, 12, 14}.
// Uses r9..r11 / eax as loop counters and scratch, xmm0..xmm2 for aesimc /
// swap.
// AES-NI instructions are db-encoded for broad assembler compatibility.
//
  mov r10d, edx
  mov r9d, 1
  mov r11d, r10d
  dec r11d
@aes_imc_loop:
  cmp r9d, r11d
  ja @aes_imc_done
  mov eax, r9d
  imul rax, rax, 16
  movdqu xmm0, [rcx + rax]
  movdqa xmm1, xmm0
  db $66, $0F, $38, $DB, $C1       // aesimc xmm0, xmm1
  movdqu [rcx + rax], xmm0
  inc r9d
  jmp @aes_imc_loop
@aes_imc_done:
  xor r9d, r9d
  mov eax, r10d
@aes_swap_loop:
  cmp r9d, eax
  jge @aes_swap_done
  movsxd r11, r9d
  imul r11, r11, 16
  movsxd r8, eax
  imul r8, r8, 16
  movdqu xmm0, [rcx + r11]
  movdqu xmm1, [rcx + r8]
  movdqu [rcx + r11], xmm1
  movdqu [rcx + r8], xmm0
  inc r9d
  dec eax
  jmp @aes_swap_loop
@aes_swap_done:
