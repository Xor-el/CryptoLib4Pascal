// Four-block AES-NI (interleaved). rcx = 64-byte state (4x16), rdx = aligned round keys, r8d = mode (Dec128..Enc256).
// xmm0..xmm3 = four blocks; xmm4 = round key.
//
  cmp r8d, 1
  je @4_d128
  cmp r8d, 2
  je @4_d192
  cmp r8d, 3
  je @4_d256
  cmp r8d, 4
  je @4_e128
  cmp r8d, 5
  je @4_e192
  cmp r8d, 6
  je @4_e256
  jmp @4_done
@4_e128:
  movdqu    xmm0, [rcx]
  movdqu    xmm1, [rcx + 16]
  movdqu    xmm2, [rcx + 32]
  movdqu    xmm3, [rcx + 48]
  movdqa    xmm4, [rdx]
  db $66, $0F, $EF, $C4                   // pxor xmm0, xmm4
  db $66, $0F, $EF, $CC                   // pxor xmm1, xmm4
  db $66, $0F, $EF, $D4                   // pxor xmm2, xmm4
  db $66, $0F, $EF, $DC                   // pxor xmm3, xmm4
  movdqa    xmm4, [rdx + 16]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 32]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 48]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 64]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 80]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 96]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 112]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 128]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 144]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 160]
  db $66, $0F, $38, $DD, $C4              // aesenclast xmm0, xmm4
  db $66, $0F, $38, $DD, $CC              // aesenclast xmm1, xmm4
  db $66, $0F, $38, $DD, $D4              // aesenclast xmm2, xmm4
  db $66, $0F, $38, $DD, $DC              // aesenclast xmm3, xmm4
  movdqu    [rcx], xmm0
  movdqu    [rcx + 16], xmm1
  movdqu    [rcx + 32], xmm2
  movdqu    [rcx + 48], xmm3
  jmp @4_done
@4_e192:
  movdqu    xmm0, [rcx]
  movdqu    xmm1, [rcx + 16]
  movdqu    xmm2, [rcx + 32]
  movdqu    xmm3, [rcx + 48]
  movdqa    xmm4, [rdx]
  db $66, $0F, $EF, $C4                   // pxor xmm0, xmm4
  db $66, $0F, $EF, $CC                   // pxor xmm1, xmm4
  db $66, $0F, $EF, $D4                   // pxor xmm2, xmm4
  db $66, $0F, $EF, $DC                   // pxor xmm3, xmm4
  movdqa    xmm4, [rdx + 16]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 32]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 48]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 64]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 80]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 96]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 112]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 128]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 144]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 160]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 176]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 192]
  db $66, $0F, $38, $DD, $C4              // aesenclast xmm0, xmm4
  db $66, $0F, $38, $DD, $CC              // aesenclast xmm1, xmm4
  db $66, $0F, $38, $DD, $D4              // aesenclast xmm2, xmm4
  db $66, $0F, $38, $DD, $DC              // aesenclast xmm3, xmm4
  movdqu    [rcx], xmm0
  movdqu    [rcx + 16], xmm1
  movdqu    [rcx + 32], xmm2
  movdqu    [rcx + 48], xmm3
  jmp @4_done
@4_e256:
  movdqu    xmm0, [rcx]
  movdqu    xmm1, [rcx + 16]
  movdqu    xmm2, [rcx + 32]
  movdqu    xmm3, [rcx + 48]
  movdqa    xmm4, [rdx]
  db $66, $0F, $EF, $C4                   // pxor xmm0, xmm4
  db $66, $0F, $EF, $CC                   // pxor xmm1, xmm4
  db $66, $0F, $EF, $D4                   // pxor xmm2, xmm4
  db $66, $0F, $EF, $DC                   // pxor xmm3, xmm4
  movdqa    xmm4, [rdx + 16]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 32]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 48]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 64]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 80]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 96]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 112]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 128]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 144]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 160]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 176]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 192]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 208]
  db $66, $0F, $38, $DC, $C4              // aesenc xmm0, xmm4
  db $66, $0F, $38, $DC, $CC              // aesenc xmm1, xmm4
  db $66, $0F, $38, $DC, $D4              // aesenc xmm2, xmm4
  db $66, $0F, $38, $DC, $DC              // aesenc xmm3, xmm4
  movdqa    xmm4, [rdx + 224]
  db $66, $0F, $38, $DD, $C4              // aesenclast xmm0, xmm4
  db $66, $0F, $38, $DD, $CC              // aesenclast xmm1, xmm4
  db $66, $0F, $38, $DD, $D4              // aesenclast xmm2, xmm4
  db $66, $0F, $38, $DD, $DC              // aesenclast xmm3, xmm4
  movdqu    [rcx], xmm0
  movdqu    [rcx + 16], xmm1
  movdqu    [rcx + 32], xmm2
  movdqu    [rcx + 48], xmm3
  jmp @4_done
@4_d128:
  movdqu    xmm0, [rcx]
  movdqu    xmm1, [rcx + 16]
  movdqu    xmm2, [rcx + 32]
  movdqu    xmm3, [rcx + 48]
  movdqa    xmm4, [rdx]
  db $66, $0F, $EF, $C4                   // pxor xmm0, xmm4
  db $66, $0F, $EF, $CC                   // pxor xmm1, xmm4
  db $66, $0F, $EF, $D4                   // pxor xmm2, xmm4
  db $66, $0F, $EF, $DC                   // pxor xmm3, xmm4
  movdqa    xmm4, [rdx + 16]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 32]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 48]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 64]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 80]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 96]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 112]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 128]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 144]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 160]
  db $66, $0F, $38, $DF, $C4              // aesdeclast xmm0, xmm4
  db $66, $0F, $38, $DF, $CC              // aesdeclast xmm1, xmm4
  db $66, $0F, $38, $DF, $D4              // aesdeclast xmm2, xmm4
  db $66, $0F, $38, $DF, $DC              // aesdeclast xmm3, xmm4
  movdqu    [rcx], xmm0
  movdqu    [rcx + 16], xmm1
  movdqu    [rcx + 32], xmm2
  movdqu    [rcx + 48], xmm3
  jmp @4_done
@4_d192:
  movdqu    xmm0, [rcx]
  movdqu    xmm1, [rcx + 16]
  movdqu    xmm2, [rcx + 32]
  movdqu    xmm3, [rcx + 48]
  movdqa    xmm4, [rdx]
  db $66, $0F, $EF, $C4                   // pxor xmm0, xmm4
  db $66, $0F, $EF, $CC                   // pxor xmm1, xmm4
  db $66, $0F, $EF, $D4                   // pxor xmm2, xmm4
  db $66, $0F, $EF, $DC                   // pxor xmm3, xmm4
  movdqa    xmm4, [rdx + 16]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 32]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 48]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 64]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 80]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 96]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 112]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 128]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 144]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 160]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 176]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 192]
  db $66, $0F, $38, $DF, $C4              // aesdeclast xmm0, xmm4
  db $66, $0F, $38, $DF, $CC              // aesdeclast xmm1, xmm4
  db $66, $0F, $38, $DF, $D4              // aesdeclast xmm2, xmm4
  db $66, $0F, $38, $DF, $DC              // aesdeclast xmm3, xmm4
  movdqu    [rcx], xmm0
  movdqu    [rcx + 16], xmm1
  movdqu    [rcx + 32], xmm2
  movdqu    [rcx + 48], xmm3
  jmp @4_done
@4_d256:
  movdqu    xmm0, [rcx]
  movdqu    xmm1, [rcx + 16]
  movdqu    xmm2, [rcx + 32]
  movdqu    xmm3, [rcx + 48]
  movdqa    xmm4, [rdx]
  db $66, $0F, $EF, $C4                   // pxor xmm0, xmm4
  db $66, $0F, $EF, $CC                   // pxor xmm1, xmm4
  db $66, $0F, $EF, $D4                   // pxor xmm2, xmm4
  db $66, $0F, $EF, $DC                   // pxor xmm3, xmm4
  movdqa    xmm4, [rdx + 16]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 32]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 48]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 64]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 80]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 96]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 112]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 128]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 144]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 160]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 176]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 192]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 208]
  db $66, $0F, $38, $DE, $C4              // aesdec xmm0, xmm4
  db $66, $0F, $38, $DE, $CC              // aesdec xmm1, xmm4
  db $66, $0F, $38, $DE, $D4              // aesdec xmm2, xmm4
  db $66, $0F, $38, $DE, $DC              // aesdec xmm3, xmm4
  movdqa    xmm4, [rdx + 224]
  db $66, $0F, $38, $DF, $C4              // aesdeclast xmm0, xmm4
  db $66, $0F, $38, $DF, $CC              // aesdeclast xmm1, xmm4
  db $66, $0F, $38, $DF, $D4              // aesdeclast xmm2, xmm4
  db $66, $0F, $38, $DF, $DC              // aesdeclast xmm3, xmm4
  movdqu    [rcx], xmm0
  movdqu    [rcx + 16], xmm1
  movdqu    [rcx + 32], xmm2
  movdqu    [rcx + 48], xmm3
@4_done:
