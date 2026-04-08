// One-block AES-NI encrypt/decrypt (scheduled round keys), x86-64.
// MS x64 ABI: rcx = 16-byte state, rdx = round keys (16-byte aligned), r8d = mode (Dec128=1 .. Enc256=6).
// State may be unaligned (movdqu); round keys use movdqa.
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
  movdqu    xmm0, [rcx]
  movdqa    xmm1, [rdx]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqa    xmm1, [rdx + 16]
  db $66, $0F, $38, $DC, $C1         // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 32]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 48]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 64]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 80]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 96]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 112]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 128]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 144]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 160]
  db $66, $0F, $38, $DD, $C1         // aesenclast xmm0, xmm1
  movdqu    [rcx], xmm0
  jmp @aes_ir_done
@aes_e192:
  movdqu    xmm0, [rcx]
  movdqa    xmm1, [rdx]
  db $66, $0F, $EF, $C1                   // pxor xmm0, xmm1
  movdqa    xmm1, [rdx + 16]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 32]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 48]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 64]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 80]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 96]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 112]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 128]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 144]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 160]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 176]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 192]
  db $66, $0F, $38, $DD, $C1              // aesenclast xmm0, xmm1
  movdqu    [rcx], xmm0
  jmp @aes_ir_done
@aes_e256:
  movdqu    xmm0, [rcx]
  movdqa    xmm1, [rdx]
  db $66, $0F, $EF, $C1                   // pxor xmm0, xmm1
  movdqa    xmm1, [rdx + 16]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 32]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 48]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 64]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 80]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 96]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 112]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 128]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 144]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 160]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 176]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 192]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 208]
  db $66, $0F, $38, $DC, $C1              // aesenc xmm0, xmm1
  movdqa    xmm1, [rdx + 224]
  db $66, $0F, $38, $DD, $C1              // aesenclast xmm0, xmm1
  movdqu    [rcx], xmm0
  jmp @aes_ir_done
@aes_d128:
  movdqu    xmm0, [rcx]
  movdqa    xmm1, [rdx]
  db $66, $0F, $EF, $C1                   // pxor xmm0, xmm1
  movdqa    xmm1, [rdx + 16]
  db $66, $0F, $38, $DE, $C1         // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 32]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 48]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 64]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 80]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 96]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 112]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 128]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 144]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 160]
  db $66, $0F, $38, $DF, $C1         // aesdeclast xmm0, xmm1
  movdqu    [rcx], xmm0
  jmp @aes_ir_done
@aes_d192:
  movdqu    xmm0, [rcx]
  movdqa    xmm1, [rdx]
  db $66, $0F, $EF, $C1                   // pxor xmm0, xmm1
  movdqa    xmm1, [rdx + 16]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 32]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 48]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 64]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 80]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 96]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 112]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 128]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 144]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 160]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 176]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 192]
  db $66, $0F, $38, $DF, $C1              // aesdeclast xmm0, xmm1
  movdqu    [rcx], xmm0
  jmp @aes_ir_done
@aes_d256:
  movdqu    xmm0, [rcx]
  movdqa    xmm1, [rdx]
  db $66, $0F, $EF, $C1                   // pxor xmm0, xmm1
  movdqa    xmm1, [rdx + 16]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 32]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 48]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 64]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 80]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 96]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 112]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 128]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 144]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 160]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 176]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 192]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 208]
  db $66, $0F, $38, $DE, $C1              // aesdec xmm0, xmm1
  movdqa    xmm1, [rdx + 224]
  db $66, $0F, $38, $DF, $C1              // aesdeclast xmm0, xmm1
  movdqu    [rcx], xmm0
@aes_ir_done:
