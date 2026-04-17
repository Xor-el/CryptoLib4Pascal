// AesNiEightEnc x86 64 (merged key sizes)
// Define exactly one of: CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256
// before including this file (see ClpAesEngineX86).
//
// True 8-wide AES-NI encrypt, in-place. rcx=state (8*16 bytes), rdx=keys.
// xmm0..xmm7 hold the 8 data blocks; xmm8 is the shared round key per round.
// AES-NI instructions are db-encoded for broad assembler compatibility.
// REX.B = 1 (prefix $41) because the source register is xmm8.
// ModRM for "xmmN, xmm8": $C0 + N*8 -> C0/C8/D0/D8/E0/E8/F0/F8 for N=0..7.

{$IFDEF CRYPTOLIB_AESNI_KEY128}
  movdqu    xmm0, [rcx]
  movdqu    xmm1, [rcx + 16]
  movdqu    xmm2, [rcx + 32]
  movdqu    xmm3, [rcx + 48]
  movdqu    xmm4, [rcx + 64]
  movdqu    xmm5, [rcx + 80]
  movdqu    xmm6, [rcx + 96]
  movdqu    xmm7, [rcx + 112]
  movdqa    xmm8, [rdx]
  db $66, $41, $0F, $EF, $C0              // pxor xmm0, xmm8
  db $66, $41, $0F, $EF, $C8              // pxor xmm1, xmm8
  db $66, $41, $0F, $EF, $D0              // pxor xmm2, xmm8
  db $66, $41, $0F, $EF, $D8              // pxor xmm3, xmm8
  db $66, $41, $0F, $EF, $E0              // pxor xmm4, xmm8
  db $66, $41, $0F, $EF, $E8              // pxor xmm5, xmm8
  db $66, $41, $0F, $EF, $F0              // pxor xmm6, xmm8
  db $66, $41, $0F, $EF, $F8              // pxor xmm7, xmm8
  movdqa    xmm8, [rdx + 16]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [rdx + 32]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [rdx + 48]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [rdx + 64]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [rdx + 80]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [rdx + 96]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [rdx + 112]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [rdx + 128]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [rdx + 144]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [rdx + 160]
  db $66, $41, $0F, $38, $DD, $C0         // aesenclast xmm0, xmm8
  db $66, $41, $0F, $38, $DD, $C8         // aesenclast xmm1, xmm8
  db $66, $41, $0F, $38, $DD, $D0         // aesenclast xmm2, xmm8
  db $66, $41, $0F, $38, $DD, $D8         // aesenclast xmm3, xmm8
  db $66, $41, $0F, $38, $DD, $E0         // aesenclast xmm4, xmm8
  db $66, $41, $0F, $38, $DD, $E8         // aesenclast xmm5, xmm8
  db $66, $41, $0F, $38, $DD, $F0         // aesenclast xmm6, xmm8
  db $66, $41, $0F, $38, $DD, $F8         // aesenclast xmm7, xmm8
  movdqu    [rcx], xmm0
  movdqu    [rcx + 16], xmm1
  movdqu    [rcx + 32], xmm2
  movdqu    [rcx + 48], xmm3
  movdqu    [rcx + 64], xmm4
  movdqu    [rcx + 80], xmm5
  movdqu    [rcx + 96], xmm6
  movdqu    [rcx + 112], xmm7
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqu    xmm0, [rcx]
  movdqu    xmm1, [rcx + 16]
  movdqu    xmm2, [rcx + 32]
  movdqu    xmm3, [rcx + 48]
  movdqu    xmm4, [rcx + 64]
  movdqu    xmm5, [rcx + 80]
  movdqu    xmm6, [rcx + 96]
  movdqu    xmm7, [rcx + 112]
  movdqa    xmm8, [rdx]
  db $66, $41, $0F, $EF, $C0              // pxor xmm0, xmm8
  db $66, $41, $0F, $EF, $C8              // pxor xmm1, xmm8
  db $66, $41, $0F, $EF, $D0              // pxor xmm2, xmm8
  db $66, $41, $0F, $EF, $D8              // pxor xmm3, xmm8
  db $66, $41, $0F, $EF, $E0              // pxor xmm4, xmm8
  db $66, $41, $0F, $EF, $E8              // pxor xmm5, xmm8
  db $66, $41, $0F, $EF, $F0              // pxor xmm6, xmm8
  db $66, $41, $0F, $EF, $F8              // pxor xmm7, xmm8
  movdqa    xmm8, [rdx + 16]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [rdx + 32]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [rdx + 48]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [rdx + 64]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [rdx + 80]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [rdx + 96]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [rdx + 112]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [rdx + 128]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [rdx + 144]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [rdx + 160]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [rdx + 176]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [rdx + 192]
  db $66, $41, $0F, $38, $DD, $C0         // aesenclast xmm0, xmm8
  db $66, $41, $0F, $38, $DD, $C8         // aesenclast xmm1, xmm8
  db $66, $41, $0F, $38, $DD, $D0         // aesenclast xmm2, xmm8
  db $66, $41, $0F, $38, $DD, $D8         // aesenclast xmm3, xmm8
  db $66, $41, $0F, $38, $DD, $E0         // aesenclast xmm4, xmm8
  db $66, $41, $0F, $38, $DD, $E8         // aesenclast xmm5, xmm8
  db $66, $41, $0F, $38, $DD, $F0         // aesenclast xmm6, xmm8
  db $66, $41, $0F, $38, $DD, $F8         // aesenclast xmm7, xmm8
  movdqu    [rcx], xmm0
  movdqu    [rcx + 16], xmm1
  movdqu    [rcx + 32], xmm2
  movdqu    [rcx + 48], xmm3
  movdqu    [rcx + 64], xmm4
  movdqu    [rcx + 80], xmm5
  movdqu    [rcx + 96], xmm6
  movdqu    [rcx + 112], xmm7
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqu    xmm0, [rcx]
  movdqu    xmm1, [rcx + 16]
  movdqu    xmm2, [rcx + 32]
  movdqu    xmm3, [rcx + 48]
  movdqu    xmm4, [rcx + 64]
  movdqu    xmm5, [rcx + 80]
  movdqu    xmm6, [rcx + 96]
  movdqu    xmm7, [rcx + 112]
  movdqa    xmm8, [rdx]
  db $66, $41, $0F, $EF, $C0              // pxor xmm0, xmm8
  db $66, $41, $0F, $EF, $C8              // pxor xmm1, xmm8
  db $66, $41, $0F, $EF, $D0              // pxor xmm2, xmm8
  db $66, $41, $0F, $EF, $D8              // pxor xmm3, xmm8
  db $66, $41, $0F, $EF, $E0              // pxor xmm4, xmm8
  db $66, $41, $0F, $EF, $E8              // pxor xmm5, xmm8
  db $66, $41, $0F, $EF, $F0              // pxor xmm6, xmm8
  db $66, $41, $0F, $EF, $F8              // pxor xmm7, xmm8
  movdqa    xmm8, [rdx + 16]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [rdx + 32]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [rdx + 48]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [rdx + 64]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [rdx + 80]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [rdx + 96]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [rdx + 112]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [rdx + 128]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [rdx + 144]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [rdx + 160]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [rdx + 176]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [rdx + 192]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [rdx + 208]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [rdx + 224]
  db $66, $41, $0F, $38, $DD, $C0         // aesenclast xmm0, xmm8
  db $66, $41, $0F, $38, $DD, $C8         // aesenclast xmm1, xmm8
  db $66, $41, $0F, $38, $DD, $D0         // aesenclast xmm2, xmm8
  db $66, $41, $0F, $38, $DD, $D8         // aesenclast xmm3, xmm8
  db $66, $41, $0F, $38, $DD, $E0         // aesenclast xmm4, xmm8
  db $66, $41, $0F, $38, $DD, $E8         // aesenclast xmm5, xmm8
  db $66, $41, $0F, $38, $DD, $F0         // aesenclast xmm6, xmm8
  db $66, $41, $0F, $38, $DD, $F8         // aesenclast xmm7, xmm8
  movdqu    [rcx], xmm0
  movdqu    [rcx + 16], xmm1
  movdqu    [rcx + 32], xmm2
  movdqu    [rcx + 48], xmm3
  movdqu    [rcx + 64], xmm4
  movdqu    [rcx + 80], xmm5
  movdqu    [rcx + 96], xmm6
  movdqu    [rcx + 112], xmm7
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}
