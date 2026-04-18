// AesNiEightCipherInOut x86_64 (merged Enc + Dec)
// Direction: define CRYPTOLIB_AESNI_DECRYPT to use the decrypt variant
// (aesdec / aesdeclast). Otherwise the encrypt variant is selected.
// Key size: define exactly one of CRYPTOLIB_AESNI_KEY128 /
// CRYPTOLIB_AESNI_KEY192 / CRYPTOLIB_AESNI_KEY256 before including
// (see ClpAesEngineX86). AES-NI instructions are db-encoded for
// broad assembler compatibility.
{$IFDEF CRYPTOLIB_AESNI_DECRYPT}
// AesNiEightDecInOut x86 64 (merged key sizes)
// Define exactly one of: CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256
// before including this file (see ClpAesEngineX86).
//
// True 8-wide AES-NI decrypt, in+out. rcx=RIn, rdx=ROut, r8=Keys.
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
  movdqa    xmm8, [r8]
  db $66, $41, $0F, $EF, $C0              // pxor xmm0, xmm8
  db $66, $41, $0F, $EF, $C8              // pxor xmm1, xmm8
  db $66, $41, $0F, $EF, $D0              // pxor xmm2, xmm8
  db $66, $41, $0F, $EF, $D8              // pxor xmm3, xmm8
  db $66, $41, $0F, $EF, $E0              // pxor xmm4, xmm8
  db $66, $41, $0F, $EF, $E8              // pxor xmm5, xmm8
  db $66, $41, $0F, $EF, $F0              // pxor xmm6, xmm8
  db $66, $41, $0F, $EF, $F8              // pxor xmm7, xmm8
  movdqa    xmm8, [r8 + 16]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 32]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 48]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 64]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 80]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 96]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 112]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 128]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 144]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 160]
  db $66, $41, $0F, $38, $DF, $C0         // aesdeclast xmm0, xmm8
  db $66, $41, $0F, $38, $DF, $C8         // aesdeclast xmm1, xmm8
  db $66, $41, $0F, $38, $DF, $D0         // aesdeclast xmm2, xmm8
  db $66, $41, $0F, $38, $DF, $D8         // aesdeclast xmm3, xmm8
  db $66, $41, $0F, $38, $DF, $E0         // aesdeclast xmm4, xmm8
  db $66, $41, $0F, $38, $DF, $E8         // aesdeclast xmm5, xmm8
  db $66, $41, $0F, $38, $DF, $F0         // aesdeclast xmm6, xmm8
  db $66, $41, $0F, $38, $DF, $F8         // aesdeclast xmm7, xmm8
  movdqu    [rdx], xmm0
  movdqu    [rdx + 16], xmm1
  movdqu    [rdx + 32], xmm2
  movdqu    [rdx + 48], xmm3
  movdqu    [rdx + 64], xmm4
  movdqu    [rdx + 80], xmm5
  movdqu    [rdx + 96], xmm6
  movdqu    [rdx + 112], xmm7
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
  movdqa    xmm8, [r8]
  db $66, $41, $0F, $EF, $C0              // pxor xmm0, xmm8
  db $66, $41, $0F, $EF, $C8              // pxor xmm1, xmm8
  db $66, $41, $0F, $EF, $D0              // pxor xmm2, xmm8
  db $66, $41, $0F, $EF, $D8              // pxor xmm3, xmm8
  db $66, $41, $0F, $EF, $E0              // pxor xmm4, xmm8
  db $66, $41, $0F, $EF, $E8              // pxor xmm5, xmm8
  db $66, $41, $0F, $EF, $F0              // pxor xmm6, xmm8
  db $66, $41, $0F, $EF, $F8              // pxor xmm7, xmm8
  movdqa    xmm8, [r8 + 16]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 32]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 48]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 64]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 80]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 96]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 112]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 128]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 144]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 160]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 176]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 192]
  db $66, $41, $0F, $38, $DF, $C0         // aesdeclast xmm0, xmm8
  db $66, $41, $0F, $38, $DF, $C8         // aesdeclast xmm1, xmm8
  db $66, $41, $0F, $38, $DF, $D0         // aesdeclast xmm2, xmm8
  db $66, $41, $0F, $38, $DF, $D8         // aesdeclast xmm3, xmm8
  db $66, $41, $0F, $38, $DF, $E0         // aesdeclast xmm4, xmm8
  db $66, $41, $0F, $38, $DF, $E8         // aesdeclast xmm5, xmm8
  db $66, $41, $0F, $38, $DF, $F0         // aesdeclast xmm6, xmm8
  db $66, $41, $0F, $38, $DF, $F8         // aesdeclast xmm7, xmm8
  movdqu    [rdx], xmm0
  movdqu    [rdx + 16], xmm1
  movdqu    [rdx + 32], xmm2
  movdqu    [rdx + 48], xmm3
  movdqu    [rdx + 64], xmm4
  movdqu    [rdx + 80], xmm5
  movdqu    [rdx + 96], xmm6
  movdqu    [rdx + 112], xmm7
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
  movdqa    xmm8, [r8]
  db $66, $41, $0F, $EF, $C0              // pxor xmm0, xmm8
  db $66, $41, $0F, $EF, $C8              // pxor xmm1, xmm8
  db $66, $41, $0F, $EF, $D0              // pxor xmm2, xmm8
  db $66, $41, $0F, $EF, $D8              // pxor xmm3, xmm8
  db $66, $41, $0F, $EF, $E0              // pxor xmm4, xmm8
  db $66, $41, $0F, $EF, $E8              // pxor xmm5, xmm8
  db $66, $41, $0F, $EF, $F0              // pxor xmm6, xmm8
  db $66, $41, $0F, $EF, $F8              // pxor xmm7, xmm8
  movdqa    xmm8, [r8 + 16]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 32]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 48]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 64]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 80]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 96]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 112]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 128]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 144]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 160]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 176]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 192]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 208]
  db $66, $41, $0F, $38, $DE, $C0         // aesdec xmm0, xmm8
  db $66, $41, $0F, $38, $DE, $C8         // aesdec xmm1, xmm8
  db $66, $41, $0F, $38, $DE, $D0         // aesdec xmm2, xmm8
  db $66, $41, $0F, $38, $DE, $D8         // aesdec xmm3, xmm8
  db $66, $41, $0F, $38, $DE, $E0         // aesdec xmm4, xmm8
  db $66, $41, $0F, $38, $DE, $E8         // aesdec xmm5, xmm8
  db $66, $41, $0F, $38, $DE, $F0         // aesdec xmm6, xmm8
  db $66, $41, $0F, $38, $DE, $F8         // aesdec xmm7, xmm8
  movdqa    xmm8, [r8 + 224]
  db $66, $41, $0F, $38, $DF, $C0         // aesdeclast xmm0, xmm8
  db $66, $41, $0F, $38, $DF, $C8         // aesdeclast xmm1, xmm8
  db $66, $41, $0F, $38, $DF, $D0         // aesdeclast xmm2, xmm8
  db $66, $41, $0F, $38, $DF, $D8         // aesdeclast xmm3, xmm8
  db $66, $41, $0F, $38, $DF, $E0         // aesdeclast xmm4, xmm8
  db $66, $41, $0F, $38, $DF, $E8         // aesdeclast xmm5, xmm8
  db $66, $41, $0F, $38, $DF, $F0         // aesdeclast xmm6, xmm8
  db $66, $41, $0F, $38, $DF, $F8         // aesdeclast xmm7, xmm8
  movdqu    [rdx], xmm0
  movdqu    [rdx + 16], xmm1
  movdqu    [rdx + 32], xmm2
  movdqu    [rdx + 48], xmm3
  movdqu    [rdx + 64], xmm4
  movdqu    [rdx + 80], xmm5
  movdqu    [rdx + 96], xmm6
  movdqu    [rdx + 112], xmm7
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

{$ELSE}
// AesNiEightEncInOut x86 64 (merged key sizes)
// Define exactly one of: CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256
// before including this file (see ClpAesEngineX86).
//
// True 8-wide AES-NI encrypt, in+out. rcx=RIn, rdx=ROut, r8=Keys.
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
  movdqa    xmm8, [r8]
  db $66, $41, $0F, $EF, $C0              // pxor xmm0, xmm8
  db $66, $41, $0F, $EF, $C8              // pxor xmm1, xmm8
  db $66, $41, $0F, $EF, $D0              // pxor xmm2, xmm8
  db $66, $41, $0F, $EF, $D8              // pxor xmm3, xmm8
  db $66, $41, $0F, $EF, $E0              // pxor xmm4, xmm8
  db $66, $41, $0F, $EF, $E8              // pxor xmm5, xmm8
  db $66, $41, $0F, $EF, $F0              // pxor xmm6, xmm8
  db $66, $41, $0F, $EF, $F8              // pxor xmm7, xmm8
  movdqa    xmm8, [r8 + 16]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 32]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 48]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 64]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 80]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 96]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 112]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 128]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 144]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 160]
  db $66, $41, $0F, $38, $DD, $C0         // aesenclast xmm0, xmm8
  db $66, $41, $0F, $38, $DD, $C8         // aesenclast xmm1, xmm8
  db $66, $41, $0F, $38, $DD, $D0         // aesenclast xmm2, xmm8
  db $66, $41, $0F, $38, $DD, $D8         // aesenclast xmm3, xmm8
  db $66, $41, $0F, $38, $DD, $E0         // aesenclast xmm4, xmm8
  db $66, $41, $0F, $38, $DD, $E8         // aesenclast xmm5, xmm8
  db $66, $41, $0F, $38, $DD, $F0         // aesenclast xmm6, xmm8
  db $66, $41, $0F, $38, $DD, $F8         // aesenclast xmm7, xmm8
  movdqu    [rdx], xmm0
  movdqu    [rdx + 16], xmm1
  movdqu    [rdx + 32], xmm2
  movdqu    [rdx + 48], xmm3
  movdqu    [rdx + 64], xmm4
  movdqu    [rdx + 80], xmm5
  movdqu    [rdx + 96], xmm6
  movdqu    [rdx + 112], xmm7
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
  movdqa    xmm8, [r8]
  db $66, $41, $0F, $EF, $C0              // pxor xmm0, xmm8
  db $66, $41, $0F, $EF, $C8              // pxor xmm1, xmm8
  db $66, $41, $0F, $EF, $D0              // pxor xmm2, xmm8
  db $66, $41, $0F, $EF, $D8              // pxor xmm3, xmm8
  db $66, $41, $0F, $EF, $E0              // pxor xmm4, xmm8
  db $66, $41, $0F, $EF, $E8              // pxor xmm5, xmm8
  db $66, $41, $0F, $EF, $F0              // pxor xmm6, xmm8
  db $66, $41, $0F, $EF, $F8              // pxor xmm7, xmm8
  movdqa    xmm8, [r8 + 16]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 32]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 48]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 64]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 80]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 96]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 112]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 128]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 144]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 160]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 176]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 192]
  db $66, $41, $0F, $38, $DD, $C0         // aesenclast xmm0, xmm8
  db $66, $41, $0F, $38, $DD, $C8         // aesenclast xmm1, xmm8
  db $66, $41, $0F, $38, $DD, $D0         // aesenclast xmm2, xmm8
  db $66, $41, $0F, $38, $DD, $D8         // aesenclast xmm3, xmm8
  db $66, $41, $0F, $38, $DD, $E0         // aesenclast xmm4, xmm8
  db $66, $41, $0F, $38, $DD, $E8         // aesenclast xmm5, xmm8
  db $66, $41, $0F, $38, $DD, $F0         // aesenclast xmm6, xmm8
  db $66, $41, $0F, $38, $DD, $F8         // aesenclast xmm7, xmm8
  movdqu    [rdx], xmm0
  movdqu    [rdx + 16], xmm1
  movdqu    [rdx + 32], xmm2
  movdqu    [rdx + 48], xmm3
  movdqu    [rdx + 64], xmm4
  movdqu    [rdx + 80], xmm5
  movdqu    [rdx + 96], xmm6
  movdqu    [rdx + 112], xmm7
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
  movdqa    xmm8, [r8]
  db $66, $41, $0F, $EF, $C0              // pxor xmm0, xmm8
  db $66, $41, $0F, $EF, $C8              // pxor xmm1, xmm8
  db $66, $41, $0F, $EF, $D0              // pxor xmm2, xmm8
  db $66, $41, $0F, $EF, $D8              // pxor xmm3, xmm8
  db $66, $41, $0F, $EF, $E0              // pxor xmm4, xmm8
  db $66, $41, $0F, $EF, $E8              // pxor xmm5, xmm8
  db $66, $41, $0F, $EF, $F0              // pxor xmm6, xmm8
  db $66, $41, $0F, $EF, $F8              // pxor xmm7, xmm8
  movdqa    xmm8, [r8 + 16]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 32]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 48]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 64]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 80]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 96]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 112]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 128]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 144]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 160]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 176]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 192]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 208]
  db $66, $41, $0F, $38, $DC, $C0         // aesenc xmm0, xmm8
  db $66, $41, $0F, $38, $DC, $C8         // aesenc xmm1, xmm8
  db $66, $41, $0F, $38, $DC, $D0         // aesenc xmm2, xmm8
  db $66, $41, $0F, $38, $DC, $D8         // aesenc xmm3, xmm8
  db $66, $41, $0F, $38, $DC, $E0         // aesenc xmm4, xmm8
  db $66, $41, $0F, $38, $DC, $E8         // aesenc xmm5, xmm8
  db $66, $41, $0F, $38, $DC, $F0         // aesenc xmm6, xmm8
  db $66, $41, $0F, $38, $DC, $F8         // aesenc xmm7, xmm8
  movdqa    xmm8, [r8 + 224]
  db $66, $41, $0F, $38, $DD, $C0         // aesenclast xmm0, xmm8
  db $66, $41, $0F, $38, $DD, $C8         // aesenclast xmm1, xmm8
  db $66, $41, $0F, $38, $DD, $D0         // aesenclast xmm2, xmm8
  db $66, $41, $0F, $38, $DD, $D8         // aesenclast xmm3, xmm8
  db $66, $41, $0F, $38, $DD, $E0         // aesenclast xmm4, xmm8
  db $66, $41, $0F, $38, $DD, $E8         // aesenclast xmm5, xmm8
  db $66, $41, $0F, $38, $DD, $F0         // aesenclast xmm6, xmm8
  db $66, $41, $0F, $38, $DD, $F8         // aesenclast xmm7, xmm8
  movdqu    [rdx], xmm0
  movdqu    [rdx + 16], xmm1
  movdqu    [rdx + 32], xmm2
  movdqu    [rdx + 48], xmm3
  movdqu    [rdx + 64], xmm4
  movdqu    [rdx + 80], xmm5
  movdqu    [rdx + 96], xmm6
  movdqu    [rdx + 112], xmm7
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

{$ENDIF}