// One-block AES-NI encrypt/decrypt (scheduled round keys), x86-64.
// Expects MS x64 ABI: rcx = 16-byte state, rdx = round keys, r8d = mode (Dec128=1 .. Enc256=6).
// Db-encoded AES-NI / SSE2 (broad assembler support).
//
  cmp r8d, 1
  je @aes_d128
  cmp r8d, 2
  je @aes_d192
  cmp r8d, 3
  je @aes_d256
  cmp r8d, 4
  je @aes_e128
  cmp r8d, 5
  je @aes_e192
  cmp r8d, 6
  je @aes_e256
  jmp @aes_ir_done
@aes_e128:
  movdqu xmm0, [rcx]
  movdqu xmm1, [rdx]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rcx], xmm0
  mov r10d, 1
@aes_e128_mid:
  cmp r10d, 9
  ja @aes_e128_last
  movdqu xmm0, [rcx]
  mov eax, r10d
  imul rax, rax, 16
  movdqu xmm1, [rdx + rax]
  db $66, $0F, $38, $DC, $C1       // aesenc xmm0, xmm1
  movdqu [rcx], xmm0
  inc r10d
  jmp @aes_e128_mid
@aes_e128_last:
  movdqu xmm0, [rcx]
  movdqu xmm1, [rdx + 160]
  db $66, $0F, $38, $DD, $C1       // aesenclast xmm0, xmm1
  movdqu [rcx], xmm0
  jmp @aes_ir_done
@aes_e192:
  movdqu xmm0, [rcx]
  movdqu xmm1, [rdx]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rcx], xmm0
  mov r10d, 1
@aes_e192_mid:
  cmp r10d, 11
  ja @aes_e192_last
  movdqu xmm0, [rcx]
  mov eax, r10d
  imul rax, rax, 16
  movdqu xmm1, [rdx + rax]
  db $66, $0F, $38, $DC, $C1       // aesenc xmm0, xmm1
  movdqu [rcx], xmm0
  inc r10d
  jmp @aes_e192_mid
@aes_e192_last:
  movdqu xmm0, [rcx]
  movdqu xmm1, [rdx + 192]
  db $66, $0F, $38, $DD, $C1       // aesenclast xmm0, xmm1
  movdqu [rcx], xmm0
  jmp @aes_ir_done
@aes_e256:
  movdqu xmm0, [rcx]
  movdqu xmm1, [rdx]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rcx], xmm0
  mov r10d, 1
@aes_e256_mid:
  cmp r10d, 13
  ja @aes_e256_last
  movdqu xmm0, [rcx]
  mov eax, r10d
  imul rax, rax, 16
  movdqu xmm1, [rdx + rax]
  db $66, $0F, $38, $DC, $C1       // aesenc xmm0, xmm1
  movdqu [rcx], xmm0
  inc r10d
  jmp @aes_e256_mid
@aes_e256_last:
  movdqu xmm0, [rcx]
  movdqu xmm1, [rdx + 224]
  db $66, $0F, $38, $DD, $C1       // aesenclast xmm0, xmm1
  movdqu [rcx], xmm0
  jmp @aes_ir_done
@aes_d128:
  movdqu xmm0, [rcx]
  movdqu xmm1, [rdx]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rcx], xmm0
  mov r10d, 1
@aes_d128_mid:
  cmp r10d, 9
  ja @aes_d128_last
  movdqu xmm0, [rcx]
  mov eax, r10d
  imul rax, rax, 16
  movdqu xmm1, [rdx + rax]
  db $66, $0F, $38, $DE, $C1       // aesdec xmm0, xmm1
  movdqu [rcx], xmm0
  inc r10d
  jmp @aes_d128_mid
@aes_d128_last:
  movdqu xmm0, [rcx]
  movdqu xmm1, [rdx + 160]
  db $66, $0F, $38, $DF, $C1       // aesdeclast xmm0, xmm1
  movdqu [rcx], xmm0
  jmp @aes_ir_done
@aes_d192:
  movdqu xmm0, [rcx]
  movdqu xmm1, [rdx]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rcx], xmm0
  mov r10d, 1
@aes_d192_mid:
  cmp r10d, 11
  ja @aes_d192_last
  movdqu xmm0, [rcx]
  mov eax, r10d
  imul rax, rax, 16
  movdqu xmm1, [rdx + rax]
  db $66, $0F, $38, $DE, $C1       // aesdec xmm0, xmm1
  movdqu [rcx], xmm0
  inc r10d
  jmp @aes_d192_mid
@aes_d192_last:
  movdqu xmm0, [rcx]
  movdqu xmm1, [rdx + 192]
  db $66, $0F, $38, $DF, $C1       // aesdeclast xmm0, xmm1
  movdqu [rcx], xmm0
  jmp @aes_ir_done
@aes_d256:
  movdqu xmm0, [rcx]
  movdqu xmm1, [rdx]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rcx], xmm0
  mov r10d, 1
@aes_d256_mid:
  cmp r10d, 13
  ja @aes_d256_last
  movdqu xmm0, [rcx]
  mov eax, r10d
  imul rax, rax, 16
  movdqu xmm1, [rdx + rax]
  db $66, $0F, $38, $DE, $C1       // aesdec xmm0, xmm1
  movdqu [rcx], xmm0
  inc r10d
  jmp @aes_d256_mid
@aes_d256_last:
  movdqu xmm0, [rcx]
  movdqu xmm1, [rdx + 224]
  db $66, $0F, $38, $DF, $C1       // aesdeclast xmm0, xmm1
  movdqu [rcx], xmm0
@aes_ir_done:
