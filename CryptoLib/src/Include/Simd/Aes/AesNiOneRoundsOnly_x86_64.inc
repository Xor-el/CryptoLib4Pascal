// AES-NI 1-wide round chain, reusable kernel, merged Enc + Dec, merged key sizes (x86-64).
// -------------------------------------------------------------------
//
// Shared 1-wide AES round chain consumed by the merged AesNiOneCipher_x86_64
// wrapper. The fused AEAD kernels (OCB / GCM / CCM / EAX) carry their
// own round chains with different register allocations and do NOT
// include this file.
//
// Variant selection:
//   CRYPTOLIB_AESNI_DECRYPT  -> aesdec / aesdeclast; else aesenc / aesenclast.
//   Exactly one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256 selects N_R
//                              (10 / 12 / 14 rounds).
//
// On entry:
//   xmm0 = 1 data block (NOT pre-whitened; K_0 XOR happens in round 0
//                  inside this file).
//   r8 = expanded round-key schedule pointer; must match the direction
//                  (decrypt consumers pass the inverse-MixColumns schedule).
//   round keys are consumed directly as [r8 + K] memory operands.
//
// On exit:
//   xmm0 = 1 post-AES block, ready for caller storeback / XOR.
//   r8 = unchanged.
//   Scratch: no xmm scratch (round keys consumed as memory operands)
//
// AES-NI instructions, plus pxor forms touching extended registers,
// are db-encoded for broad assembler compatibility.
{$IFDEF CRYPTOLIB_AESNI_DECRYPT}

{$IFDEF CRYPTOLIB_AESNI_KEY128}
  db $66, $41, $0F, $EF, $00              // pxor xmm0, [r8+0]
  db $66, $41, $0F, $38, $DE, $40, $10    // aesdec xmm0, [r8+16]
  db $66, $41, $0F, $38, $DE, $40, $20    // aesdec xmm0, [r8+32]
  db $66, $41, $0F, $38, $DE, $40, $30    // aesdec xmm0, [r8+48]
  db $66, $41, $0F, $38, $DE, $40, $40    // aesdec xmm0, [r8+64]
  db $66, $41, $0F, $38, $DE, $40, $50    // aesdec xmm0, [r8+80]
  db $66, $41, $0F, $38, $DE, $40, $60    // aesdec xmm0, [r8+96]
  db $66, $41, $0F, $38, $DE, $40, $70    // aesdec xmm0, [r8+112]
  db $66, $41, $0F, $38, $DE, $80, $80, $00, $00, $00 // aesdec xmm0, [r8+128]
  db $66, $41, $0F, $38, $DE, $80, $90, $00, $00, $00 // aesdec xmm0, [r8+144]
  db $66, $41, $0F, $38, $DF, $80, $A0, $00, $00, $00 // aesdeclast xmm0, [r8+160]
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
  db $66, $41, $0F, $EF, $00              // pxor xmm0, [r8+0]
  db $66, $41, $0F, $38, $DE, $40, $10    // aesdec xmm0, [r8+16]
  db $66, $41, $0F, $38, $DE, $40, $20    // aesdec xmm0, [r8+32]
  db $66, $41, $0F, $38, $DE, $40, $30    // aesdec xmm0, [r8+48]
  db $66, $41, $0F, $38, $DE, $40, $40    // aesdec xmm0, [r8+64]
  db $66, $41, $0F, $38, $DE, $40, $50    // aesdec xmm0, [r8+80]
  db $66, $41, $0F, $38, $DE, $40, $60    // aesdec xmm0, [r8+96]
  db $66, $41, $0F, $38, $DE, $40, $70    // aesdec xmm0, [r8+112]
  db $66, $41, $0F, $38, $DE, $80, $80, $00, $00, $00 // aesdec xmm0, [r8+128]
  db $66, $41, $0F, $38, $DE, $80, $90, $00, $00, $00 // aesdec xmm0, [r8+144]
  db $66, $41, $0F, $38, $DE, $80, $A0, $00, $00, $00 // aesdec xmm0, [r8+160]
  db $66, $41, $0F, $38, $DE, $80, $B0, $00, $00, $00 // aesdec xmm0, [r8+176]
  db $66, $41, $0F, $38, $DF, $80, $C0, $00, $00, $00 // aesdeclast xmm0, [r8+192]
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
  db $66, $41, $0F, $EF, $00              // pxor xmm0, [r8+0]
  db $66, $41, $0F, $38, $DE, $40, $10    // aesdec xmm0, [r8+16]
  db $66, $41, $0F, $38, $DE, $40, $20    // aesdec xmm0, [r8+32]
  db $66, $41, $0F, $38, $DE, $40, $30    // aesdec xmm0, [r8+48]
  db $66, $41, $0F, $38, $DE, $40, $40    // aesdec xmm0, [r8+64]
  db $66, $41, $0F, $38, $DE, $40, $50    // aesdec xmm0, [r8+80]
  db $66, $41, $0F, $38, $DE, $40, $60    // aesdec xmm0, [r8+96]
  db $66, $41, $0F, $38, $DE, $40, $70    // aesdec xmm0, [r8+112]
  db $66, $41, $0F, $38, $DE, $80, $80, $00, $00, $00 // aesdec xmm0, [r8+128]
  db $66, $41, $0F, $38, $DE, $80, $90, $00, $00, $00 // aesdec xmm0, [r8+144]
  db $66, $41, $0F, $38, $DE, $80, $A0, $00, $00, $00 // aesdec xmm0, [r8+160]
  db $66, $41, $0F, $38, $DE, $80, $B0, $00, $00, $00 // aesdec xmm0, [r8+176]
  db $66, $41, $0F, $38, $DE, $80, $C0, $00, $00, $00 // aesdec xmm0, [r8+192]
  db $66, $41, $0F, $38, $DE, $80, $D0, $00, $00, $00 // aesdec xmm0, [r8+208]
  db $66, $41, $0F, $38, $DF, $80, $E0, $00, $00, $00 // aesdeclast xmm0, [r8+224]
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

{$ELSE}

{$IFDEF CRYPTOLIB_AESNI_KEY128}
  db $66, $41, $0F, $EF, $00              // pxor xmm0, [r8+0]
  db $66, $41, $0F, $38, $DC, $40, $10    // aesenc xmm0, [r8+16]
  db $66, $41, $0F, $38, $DC, $40, $20    // aesenc xmm0, [r8+32]
  db $66, $41, $0F, $38, $DC, $40, $30    // aesenc xmm0, [r8+48]
  db $66, $41, $0F, $38, $DC, $40, $40    // aesenc xmm0, [r8+64]
  db $66, $41, $0F, $38, $DC, $40, $50    // aesenc xmm0, [r8+80]
  db $66, $41, $0F, $38, $DC, $40, $60    // aesenc xmm0, [r8+96]
  db $66, $41, $0F, $38, $DC, $40, $70    // aesenc xmm0, [r8+112]
  db $66, $41, $0F, $38, $DC, $80, $80, $00, $00, $00 // aesenc xmm0, [r8+128]
  db $66, $41, $0F, $38, $DC, $80, $90, $00, $00, $00 // aesenc xmm0, [r8+144]
  db $66, $41, $0F, $38, $DD, $80, $A0, $00, $00, $00 // aesenclast xmm0, [r8+160]
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
  db $66, $41, $0F, $EF, $00              // pxor xmm0, [r8+0]
  db $66, $41, $0F, $38, $DC, $40, $10    // aesenc xmm0, [r8+16]
  db $66, $41, $0F, $38, $DC, $40, $20    // aesenc xmm0, [r8+32]
  db $66, $41, $0F, $38, $DC, $40, $30    // aesenc xmm0, [r8+48]
  db $66, $41, $0F, $38, $DC, $40, $40    // aesenc xmm0, [r8+64]
  db $66, $41, $0F, $38, $DC, $40, $50    // aesenc xmm0, [r8+80]
  db $66, $41, $0F, $38, $DC, $40, $60    // aesenc xmm0, [r8+96]
  db $66, $41, $0F, $38, $DC, $40, $70    // aesenc xmm0, [r8+112]
  db $66, $41, $0F, $38, $DC, $80, $80, $00, $00, $00 // aesenc xmm0, [r8+128]
  db $66, $41, $0F, $38, $DC, $80, $90, $00, $00, $00 // aesenc xmm0, [r8+144]
  db $66, $41, $0F, $38, $DC, $80, $A0, $00, $00, $00 // aesenc xmm0, [r8+160]
  db $66, $41, $0F, $38, $DC, $80, $B0, $00, $00, $00 // aesenc xmm0, [r8+176]
  db $66, $41, $0F, $38, $DD, $80, $C0, $00, $00, $00 // aesenclast xmm0, [r8+192]
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
  db $66, $41, $0F, $EF, $00              // pxor xmm0, [r8+0]
  db $66, $41, $0F, $38, $DC, $40, $10    // aesenc xmm0, [r8+16]
  db $66, $41, $0F, $38, $DC, $40, $20    // aesenc xmm0, [r8+32]
  db $66, $41, $0F, $38, $DC, $40, $30    // aesenc xmm0, [r8+48]
  db $66, $41, $0F, $38, $DC, $40, $40    // aesenc xmm0, [r8+64]
  db $66, $41, $0F, $38, $DC, $40, $50    // aesenc xmm0, [r8+80]
  db $66, $41, $0F, $38, $DC, $40, $60    // aesenc xmm0, [r8+96]
  db $66, $41, $0F, $38, $DC, $40, $70    // aesenc xmm0, [r8+112]
  db $66, $41, $0F, $38, $DC, $80, $80, $00, $00, $00 // aesenc xmm0, [r8+128]
  db $66, $41, $0F, $38, $DC, $80, $90, $00, $00, $00 // aesenc xmm0, [r8+144]
  db $66, $41, $0F, $38, $DC, $80, $A0, $00, $00, $00 // aesenc xmm0, [r8+160]
  db $66, $41, $0F, $38, $DC, $80, $B0, $00, $00, $00 // aesenc xmm0, [r8+176]
  db $66, $41, $0F, $38, $DC, $80, $C0, $00, $00, $00 // aesenc xmm0, [r8+192]
  db $66, $41, $0F, $38, $DC, $80, $D0, $00, $00, $00 // aesenc xmm0, [r8+208]
  db $66, $41, $0F, $38, $DD, $80, $E0, $00, $00, $00 // aesenclast xmm0, [r8+224]
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

{$ENDIF}
