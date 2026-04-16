// Straight-line one-block AES-NI (@aes_d128), x86-64. rcx=state, rdx=keys.
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
