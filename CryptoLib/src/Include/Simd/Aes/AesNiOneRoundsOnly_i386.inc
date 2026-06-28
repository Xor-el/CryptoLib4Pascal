// AES-NI 1-wide round chain, reusable kernel, merged Enc + Dec, merged key sizes (i386).
// -------------------------------------------------------------------
//
// Shared 1-wide AES round chain consumed by the merged AesNiOneCipher_i386
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
//   edi = expanded round-key schedule pointer; must match the direction
//                  (decrypt consumers pass the inverse-MixColumns schedule).
//   round keys are consumed directly as [edi + K] memory operands.
//
// On exit:
//   xmm0 = 1 post-AES block, ready for caller storeback / XOR.
//   edi = unchanged.
//   Scratch: no xmm scratch (round keys consumed as memory operands)
//
// AES-NI instructions, plus pxor forms touching extended registers,
// are db-encoded for broad assembler compatibility.
{$IFDEF CRYPTOLIB_AESNI_DECRYPT}

{$IFDEF CRYPTOLIB_AESNI_KEY128}
  db $66, $0F, $EF, $07   // pxor xmm0, [edi+0]
  db $66, $0F, $38, $DE, $47, $10   // aesdec xmm0, [edi+16]
  db $66, $0F, $38, $DE, $47, $20   // aesdec xmm0, [edi+32]
  db $66, $0F, $38, $DE, $47, $30   // aesdec xmm0, [edi+48]
  db $66, $0F, $38, $DE, $47, $40   // aesdec xmm0, [edi+64]
  db $66, $0F, $38, $DE, $47, $50   // aesdec xmm0, [edi+80]
  db $66, $0F, $38, $DE, $47, $60   // aesdec xmm0, [edi+96]
  db $66, $0F, $38, $DE, $47, $70   // aesdec xmm0, [edi+112]
  db $66, $0F, $38, $DE, $87, $80, $00, $00, $00   // aesdec xmm0, [edi+128]
  db $66, $0F, $38, $DE, $87, $90, $00, $00, $00   // aesdec xmm0, [edi+144]
  db $66, $0F, $38, $DF, $87, $A0, $00, $00, $00   // aesdeclast xmm0, [edi+160]
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
  db $66, $0F, $EF, $07   // pxor xmm0, [edi+0]
  db $66, $0F, $38, $DE, $47, $10   // aesdec xmm0, [edi+16]
  db $66, $0F, $38, $DE, $47, $20   // aesdec xmm0, [edi+32]
  db $66, $0F, $38, $DE, $47, $30   // aesdec xmm0, [edi+48]
  db $66, $0F, $38, $DE, $47, $40   // aesdec xmm0, [edi+64]
  db $66, $0F, $38, $DE, $47, $50   // aesdec xmm0, [edi+80]
  db $66, $0F, $38, $DE, $47, $60   // aesdec xmm0, [edi+96]
  db $66, $0F, $38, $DE, $47, $70   // aesdec xmm0, [edi+112]
  db $66, $0F, $38, $DE, $87, $80, $00, $00, $00   // aesdec xmm0, [edi+128]
  db $66, $0F, $38, $DE, $87, $90, $00, $00, $00   // aesdec xmm0, [edi+144]
  db $66, $0F, $38, $DE, $87, $A0, $00, $00, $00   // aesdec xmm0, [edi+160]
  db $66, $0F, $38, $DE, $87, $B0, $00, $00, $00   // aesdec xmm0, [edi+176]
  db $66, $0F, $38, $DF, $87, $C0, $00, $00, $00   // aesdeclast xmm0, [edi+192]
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
  db $66, $0F, $EF, $07   // pxor xmm0, [edi+0]
  db $66, $0F, $38, $DE, $47, $10   // aesdec xmm0, [edi+16]
  db $66, $0F, $38, $DE, $47, $20   // aesdec xmm0, [edi+32]
  db $66, $0F, $38, $DE, $47, $30   // aesdec xmm0, [edi+48]
  db $66, $0F, $38, $DE, $47, $40   // aesdec xmm0, [edi+64]
  db $66, $0F, $38, $DE, $47, $50   // aesdec xmm0, [edi+80]
  db $66, $0F, $38, $DE, $47, $60   // aesdec xmm0, [edi+96]
  db $66, $0F, $38, $DE, $47, $70   // aesdec xmm0, [edi+112]
  db $66, $0F, $38, $DE, $87, $80, $00, $00, $00   // aesdec xmm0, [edi+128]
  db $66, $0F, $38, $DE, $87, $90, $00, $00, $00   // aesdec xmm0, [edi+144]
  db $66, $0F, $38, $DE, $87, $A0, $00, $00, $00   // aesdec xmm0, [edi+160]
  db $66, $0F, $38, $DE, $87, $B0, $00, $00, $00   // aesdec xmm0, [edi+176]
  db $66, $0F, $38, $DE, $87, $C0, $00, $00, $00   // aesdec xmm0, [edi+192]
  db $66, $0F, $38, $DE, $87, $D0, $00, $00, $00   // aesdec xmm0, [edi+208]
  db $66, $0F, $38, $DF, $87, $E0, $00, $00, $00   // aesdeclast xmm0, [edi+224]
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

{$ELSE}

{$IFDEF CRYPTOLIB_AESNI_KEY128}
  db $66, $0F, $EF, $07   // pxor xmm0, [edi+0]
  db $66, $0F, $38, $DC, $47, $10   // aesenc xmm0, [edi+16]
  db $66, $0F, $38, $DC, $47, $20   // aesenc xmm0, [edi+32]
  db $66, $0F, $38, $DC, $47, $30   // aesenc xmm0, [edi+48]
  db $66, $0F, $38, $DC, $47, $40   // aesenc xmm0, [edi+64]
  db $66, $0F, $38, $DC, $47, $50   // aesenc xmm0, [edi+80]
  db $66, $0F, $38, $DC, $47, $60   // aesenc xmm0, [edi+96]
  db $66, $0F, $38, $DC, $47, $70   // aesenc xmm0, [edi+112]
  db $66, $0F, $38, $DC, $87, $80, $00, $00, $00   // aesenc xmm0, [edi+128]
  db $66, $0F, $38, $DC, $87, $90, $00, $00, $00   // aesenc xmm0, [edi+144]
  db $66, $0F, $38, $DD, $87, $A0, $00, $00, $00   // aesenclast xmm0, [edi+160]
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
  db $66, $0F, $EF, $07   // pxor xmm0, [edi+0]
  db $66, $0F, $38, $DC, $47, $10   // aesenc xmm0, [edi+16]
  db $66, $0F, $38, $DC, $47, $20   // aesenc xmm0, [edi+32]
  db $66, $0F, $38, $DC, $47, $30   // aesenc xmm0, [edi+48]
  db $66, $0F, $38, $DC, $47, $40   // aesenc xmm0, [edi+64]
  db $66, $0F, $38, $DC, $47, $50   // aesenc xmm0, [edi+80]
  db $66, $0F, $38, $DC, $47, $60   // aesenc xmm0, [edi+96]
  db $66, $0F, $38, $DC, $47, $70   // aesenc xmm0, [edi+112]
  db $66, $0F, $38, $DC, $87, $80, $00, $00, $00   // aesenc xmm0, [edi+128]
  db $66, $0F, $38, $DC, $87, $90, $00, $00, $00   // aesenc xmm0, [edi+144]
  db $66, $0F, $38, $DC, $87, $A0, $00, $00, $00   // aesenc xmm0, [edi+160]
  db $66, $0F, $38, $DC, $87, $B0, $00, $00, $00   // aesenc xmm0, [edi+176]
  db $66, $0F, $38, $DD, $87, $C0, $00, $00, $00   // aesenclast xmm0, [edi+192]
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
  db $66, $0F, $EF, $07   // pxor xmm0, [edi+0]
  db $66, $0F, $38, $DC, $47, $10   // aesenc xmm0, [edi+16]
  db $66, $0F, $38, $DC, $47, $20   // aesenc xmm0, [edi+32]
  db $66, $0F, $38, $DC, $47, $30   // aesenc xmm0, [edi+48]
  db $66, $0F, $38, $DC, $47, $40   // aesenc xmm0, [edi+64]
  db $66, $0F, $38, $DC, $47, $50   // aesenc xmm0, [edi+80]
  db $66, $0F, $38, $DC, $47, $60   // aesenc xmm0, [edi+96]
  db $66, $0F, $38, $DC, $47, $70   // aesenc xmm0, [edi+112]
  db $66, $0F, $38, $DC, $87, $80, $00, $00, $00   // aesenc xmm0, [edi+128]
  db $66, $0F, $38, $DC, $87, $90, $00, $00, $00   // aesenc xmm0, [edi+144]
  db $66, $0F, $38, $DC, $87, $A0, $00, $00, $00   // aesenc xmm0, [edi+160]
  db $66, $0F, $38, $DC, $87, $B0, $00, $00, $00   // aesenc xmm0, [edi+176]
  db $66, $0F, $38, $DC, $87, $C0, $00, $00, $00   // aesenc xmm0, [edi+192]
  db $66, $0F, $38, $DC, $87, $D0, $00, $00, $00   // aesenc xmm0, [edi+208]
  db $66, $0F, $38, $DD, $87, $E0, $00, $00, $00   // aesenclast xmm0, [edi+224]
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

{$ENDIF}
