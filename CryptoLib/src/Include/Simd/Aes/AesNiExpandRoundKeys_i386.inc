// AES-NI key-expansion kernel, merged key sizes (i386).
// Expands a single user key into N_R + 1 round keys, each 16 bytes, using
// aeskeygenassist + pshufd + pxor / pslldq per the standard AES-128 / 192 / 256
// schedules. N_R = 10 / 12 / 14 rounds, producing 11 / 13 / 15 round keys.
//
// Variant selection:
//   Exactly one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256 selects the
//   schedule width (see ClpAesEngineX86 for the allocation site).
//
// Entry (after SimdProc2Begin_i386): ebx = user key (16 / 24 / 32 bytes),
// esi = KeysOut (16 * (N_R + 1) bytes).
// Saves edi and ebx on the stack; uses 48 bytes of scratch at
// esp + 0 / +16 / +32 (Ls1 / Lt1 / Lw).
// Uses xmm0..xmm2 (scratch).
// AES-NI instructions are db-encoded for broad assembler compatibility.

{$IFDEF CRYPTOLIB_AESNI_KEY128}
// AES-128 encryption round-key expansion, i386.
// After SimdProc2Begin_i386: ebx = 16-byte key, esi = KeysOut (11 * 16 bytes).
// Stack: Ls1, Lt1, Lw; edi = KeysOut. Saves edi, ebx (key ptr on stack).
// AES-NI instructions are db-encoded for broad assembler compatibility.
//
  push edi
  push ebx
  sub esp, 48
  mov edi, esi
  movdqu xmm0, [ebx]
  movdqu [esp], xmm0
  movdqu [edi], xmm0

// ----- round 0 -> K[1], rcon $01 -----
  lea eax, [esp + 16]
  lea ebx, [esp]
  movdqu xmm2, [ebx]
  db $66, $0F, $3A, $DF, $CA, $01   // aeskeygenassist xmm1, xmm2, $01
  movdqu [eax], xmm1
  movdqu xmm0, [eax]
  db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
  movdqu [eax], xmm0
  movdqu xmm0, [esp]
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp]
  movdqu xmm1, [esp + 32]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [esp], xmm0
  movdqu xmm0, [esp + 16]
  movdqu xmm1, [esp]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [esp + 16], xmm0
  movdqu xmm0, [esp]
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  movdqu xmm1, [esp + 16]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  movdqu [esp], xmm0
  movdqu xmm0, [esp]
  movdqu [edi + 16], xmm0

// ----- round 1, rcon $02 -----
  lea eax, [esp + 16]
  lea ebx, [esp]
  movdqu xmm2, [ebx]
  db $66, $0F, $3A, $DF, $CA, $02   // aeskeygenassist xmm1, xmm2, $02
  movdqu [eax], xmm1
  movdqu xmm0, [eax]
  db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
  movdqu [eax], xmm0
  movdqu xmm0, [esp]
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp]
  movdqu xmm1, [esp + 32]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [esp], xmm0
  movdqu xmm0, [esp + 16]
  movdqu xmm1, [esp]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [esp + 16], xmm0
  movdqu xmm0, [esp]
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  movdqu xmm1, [esp + 16]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  movdqu [esp], xmm0
  movdqu xmm0, [esp]
  movdqu [edi + 32], xmm0

// ----- round 2, rcon $04 -----
  lea eax, [esp + 16]
  lea ebx, [esp]
  movdqu xmm2, [ebx]
  db $66, $0F, $3A, $DF, $CA, $04   // aeskeygenassist xmm1, xmm2, $04
  movdqu [eax], xmm1
  movdqu xmm0, [eax]
  db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
  movdqu [eax], xmm0
  movdqu xmm0, [esp]
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp]
  movdqu xmm1, [esp + 32]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [esp], xmm0
  movdqu xmm0, [esp + 16]
  movdqu xmm1, [esp]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [esp + 16], xmm0
  movdqu xmm0, [esp]
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  movdqu xmm1, [esp + 16]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  movdqu [esp], xmm0
  movdqu xmm0, [esp]
  movdqu [edi + 48], xmm0

// ----- round 3, rcon $08 -----
  lea eax, [esp + 16]
  lea ebx, [esp]
  movdqu xmm2, [ebx]
  db $66, $0F, $3A, $DF, $CA, $08   // aeskeygenassist xmm1, xmm2, $08
  movdqu [eax], xmm1
  movdqu xmm0, [eax]
  db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
  movdqu [eax], xmm0
  movdqu xmm0, [esp]
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp]
  movdqu xmm1, [esp + 32]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [esp], xmm0
  movdqu xmm0, [esp + 16]
  movdqu xmm1, [esp]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [esp + 16], xmm0
  movdqu xmm0, [esp]
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  movdqu xmm1, [esp + 16]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  movdqu [esp], xmm0
  movdqu xmm0, [esp]
  movdqu [edi + 64], xmm0

// ----- round 4, rcon $10 -----
  lea eax, [esp + 16]
  lea ebx, [esp]
  movdqu xmm2, [ebx]
  db $66, $0F, $3A, $DF, $CA, $10   // aeskeygenassist xmm1, xmm2, $10
  movdqu [eax], xmm1
  movdqu xmm0, [eax]
  db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
  movdqu [eax], xmm0
  movdqu xmm0, [esp]
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp]
  movdqu xmm1, [esp + 32]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [esp], xmm0
  movdqu xmm0, [esp + 16]
  movdqu xmm1, [esp]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [esp + 16], xmm0
  movdqu xmm0, [esp]
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  movdqu xmm1, [esp + 16]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  movdqu [esp], xmm0
  movdqu xmm0, [esp]
  movdqu [edi + 80], xmm0

// ----- round 5, rcon $20 -----
  lea eax, [esp + 16]
  lea ebx, [esp]
  movdqu xmm2, [ebx]
  db $66, $0F, $3A, $DF, $CA, $20   // aeskeygenassist xmm1, xmm2, $20
  movdqu [eax], xmm1
  movdqu xmm0, [eax]
  db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
  movdqu [eax], xmm0
  movdqu xmm0, [esp]
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp]
  movdqu xmm1, [esp + 32]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [esp], xmm0
  movdqu xmm0, [esp + 16]
  movdqu xmm1, [esp]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [esp + 16], xmm0
  movdqu xmm0, [esp]
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  movdqu xmm1, [esp + 16]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  movdqu [esp], xmm0
  movdqu xmm0, [esp]
  movdqu [edi + 96], xmm0

// ----- round 6, rcon $40 -----
  lea eax, [esp + 16]
  lea ebx, [esp]
  movdqu xmm2, [ebx]
  db $66, $0F, $3A, $DF, $CA, $40   // aeskeygenassist xmm1, xmm2, $40
  movdqu [eax], xmm1
  movdqu xmm0, [eax]
  db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
  movdqu [eax], xmm0
  movdqu xmm0, [esp]
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp]
  movdqu xmm1, [esp + 32]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [esp], xmm0
  movdqu xmm0, [esp + 16]
  movdqu xmm1, [esp]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [esp + 16], xmm0
  movdqu xmm0, [esp]
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  movdqu xmm1, [esp + 16]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  movdqu [esp], xmm0
  movdqu xmm0, [esp]
  movdqu [edi + 112], xmm0

// ----- round 7, rcon $80 -----
  lea eax, [esp + 16]
  lea ebx, [esp]
  movdqu xmm2, [ebx]
  db $66, $0F, $3A, $DF, $CA, $80   // aeskeygenassist xmm1, xmm2, $80
  movdqu [eax], xmm1
  movdqu xmm0, [eax]
  db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
  movdqu [eax], xmm0
  movdqu xmm0, [esp]
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp]
  movdqu xmm1, [esp + 32]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [esp], xmm0
  movdqu xmm0, [esp + 16]
  movdqu xmm1, [esp]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [esp + 16], xmm0
  movdqu xmm0, [esp]
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  movdqu xmm1, [esp + 16]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  movdqu [esp], xmm0
  movdqu xmm0, [esp]
  movdqu [edi + 128], xmm0

// ----- round 8, rcon $1B -----
  lea eax, [esp + 16]
  lea ebx, [esp]
  movdqu xmm2, [ebx]
  db $66, $0F, $3A, $DF, $CA, $1B   // aeskeygenassist xmm1, xmm2, $1B
  movdqu [eax], xmm1
  movdqu xmm0, [eax]
  db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
  movdqu [eax], xmm0
  movdqu xmm0, [esp]
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp]
  movdqu xmm1, [esp + 32]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [esp], xmm0
  movdqu xmm0, [esp + 16]
  movdqu xmm1, [esp]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [esp + 16], xmm0
  movdqu xmm0, [esp]
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  movdqu xmm1, [esp + 16]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  movdqu [esp], xmm0
  movdqu xmm0, [esp]
  movdqu [edi + 144], xmm0

// ----- round 9, rcon $36 -> K[10] -----
  lea eax, [esp + 16]
  lea ebx, [esp]
  movdqu xmm2, [ebx]
  db $66, $0F, $3A, $DF, $CA, $36   // aeskeygenassist xmm1, xmm2, $36
  movdqu [eax], xmm1
  movdqu xmm0, [eax]
  db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
  movdqu [eax], xmm0
  movdqu xmm0, [esp]
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp]
  movdqu xmm1, [esp + 32]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [esp], xmm0
  movdqu xmm0, [esp + 16]
  movdqu xmm1, [esp]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [esp + 16], xmm0
  movdqu xmm0, [esp]
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  movdqu xmm1, [esp + 16]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [esp + 32], xmm0
  movdqu xmm0, [esp + 32]
  movdqu [esp], xmm0
  movdqu xmm0, [esp]
  movdqu [edi + 160], xmm0

  add esp, 48
  pop ebx
  pop edi
  pop esi
  pop ebx
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
  // AES-192 encryption round-key expansion, i386.
  // After SimdProc2Begin_i386: ebx = 24-byte key, esi = KeysOut (13 * 16 bytes).
  // Stack: S1,S2,S3,T1,T2,W; edi = KeysOut. Saves edi, ebx (key ptr on stack).
  // AES-NI instructions are db-encoded for broad assembler compatibility.
  //
    push edi
    push ebx
    sub esp, 96
    mov edi, esi
    movdqu xmm0, [ebx]
    movdqu [esp], xmm0
    movdqu [edi], xmm0
    pxor xmm0, xmm0
    movdqu [esp + 16], xmm0
    db $F3, $0F, $7E, $43, $10   // movq xmm0, qword ptr [ebx + 16]
    movdqu [esp + 16], xmm0

    lea eax, [esp + 48]
    lea ebx, [esp + 16]
    movdqu xmm2, [ebx]
    db $66, $0F, $3A, $DF, $CA, $01   // aeskeygenassist xmm1, xmm2, $01
    movdqu [eax], xmm1
    movdqu xmm0, [esp + 48]
    db $66, $0F, $70, $C0, $55        // pshufd xmm0, xmm0, $55
    movdqu [esp + 48], xmm0
    movdqu xmm0, [esp]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp]
    movdqu xmm1, [esp + 80]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp], xmm0
    movdqu xmm0, [esp + 48]
    movdqu xmm1, [esp]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 48], xmm0
    movdqu xmm0, [esp]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu xmm1, [esp + 48]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu [esp], xmm0
    movdqu xmm0, [esp + 16]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp]
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 64]
    db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 80]
    movdqu xmm1, [esp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu [edi + 16], xmm0
    movdqu xmm0, [esp]
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 64]
    db $66, $0F, $73, $D8, $0C        // psrldq xmm0, $0C
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 16]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu xmm1, [esp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu [esp + 32], xmm0
    movdqu xmm0, [esp + 32]
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 64]
    db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 32]
    movdqu xmm1, [esp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 32], xmm0
    movdqu xmm0, [esp]
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 64]
    db $66, $0F, $73, $D8, $08        // psrldq xmm0, $08
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 64]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 32]
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 64]
    db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 80]
    movdqu xmm1, [esp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu [edi + 32], xmm0
    lea eax, [esp + 64]
    lea ebx, [esp + 32]
    movdqu xmm2, [ebx]
    db $66, $0F, $3A, $DF, $CA, $02   // aeskeygenassist xmm1, xmm2, $02
    movdqu [eax], xmm1
    movdqu xmm0, [esp + 64]
    db $66, $0F, $70, $C0, $55        // pshufd xmm0, xmm0, $55
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp]
    movdqu xmm1, [esp + 80]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp], xmm0
    movdqu xmm0, [esp + 64]
    movdqu xmm1, [esp]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu xmm1, [esp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu [esp], xmm0
    movdqu xmm0, [esp]
    movdqu [edi + 48], xmm0
    movdqu xmm0, [esp]
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 64]
    db $66, $0F, $73, $D8, $0C        // psrldq xmm0, $0C
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 32]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu xmm1, [esp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu [esp + 16], xmm0
    movdqu xmm0, [esp + 16]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 16]
    movdqu xmm1, [esp + 80]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 16], xmm0
    mov dword ptr [esp + 24], 0
    mov dword ptr [esp + 28], 0
    lea eax, [esp + 48]
    lea ebx, [esp + 16]
    movdqu xmm2, [ebx]
    db $66, $0F, $3A, $DF, $CA, $04   // aeskeygenassist xmm1, xmm2, $04
    movdqu [eax], xmm1
    movdqu xmm0, [esp + 48]
    db $66, $0F, $70, $C0, $55        // pshufd xmm0, xmm0, $55
    movdqu [esp + 48], xmm0
    movdqu xmm0, [esp]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp]
    movdqu xmm1, [esp + 80]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp], xmm0
    movdqu xmm0, [esp + 48]
    movdqu xmm1, [esp]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 48], xmm0
    movdqu xmm0, [esp]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu xmm1, [esp + 48]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu [esp], xmm0
    movdqu xmm0, [esp + 16]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp]
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 64]
    db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 80]
    movdqu xmm1, [esp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu [edi + 64], xmm0
    movdqu xmm0, [esp]
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 64]
    db $66, $0F, $73, $D8, $0C        // psrldq xmm0, $0C
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 16]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu xmm1, [esp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu [esp + 32], xmm0
    movdqu xmm0, [esp + 32]
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 64]
    db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 32]
    movdqu xmm1, [esp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 32], xmm0
    movdqu xmm0, [esp]
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 64]
    db $66, $0F, $73, $D8, $08        // psrldq xmm0, $08
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 64]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 32]
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 64]
    db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 80]
    movdqu xmm1, [esp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu [edi + 80], xmm0
    lea eax, [esp + 64]
    lea ebx, [esp + 32]
    movdqu xmm2, [ebx]
    db $66, $0F, $3A, $DF, $CA, $08   // aeskeygenassist xmm1, xmm2, $08
    movdqu [eax], xmm1
    movdqu xmm0, [esp + 64]
    db $66, $0F, $70, $C0, $55        // pshufd xmm0, xmm0, $55
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp]
    movdqu xmm1, [esp + 80]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp], xmm0
    movdqu xmm0, [esp + 64]
    movdqu xmm1, [esp]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu xmm1, [esp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu [esp], xmm0
    movdqu xmm0, [esp]
    movdqu [edi + 96], xmm0
    movdqu xmm0, [esp]
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 64]
    db $66, $0F, $73, $D8, $0C        // psrldq xmm0, $0C
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 32]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu xmm1, [esp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu [esp + 16], xmm0
    movdqu xmm0, [esp + 16]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 16]
    movdqu xmm1, [esp + 80]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 16], xmm0
    mov dword ptr [esp + 24], 0
    mov dword ptr [esp + 28], 0
    lea eax, [esp + 48]
    lea ebx, [esp + 16]
    movdqu xmm2, [ebx]
    db $66, $0F, $3A, $DF, $CA, $10   // aeskeygenassist xmm1, xmm2, $10
    movdqu [eax], xmm1
    movdqu xmm0, [esp + 48]
    db $66, $0F, $70, $C0, $55        // pshufd xmm0, xmm0, $55
    movdqu [esp + 48], xmm0
    movdqu xmm0, [esp]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp]
    movdqu xmm1, [esp + 80]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp], xmm0
    movdqu xmm0, [esp + 48]
    movdqu xmm1, [esp]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 48], xmm0
    movdqu xmm0, [esp]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu xmm1, [esp + 48]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu [esp], xmm0
    movdqu xmm0, [esp + 16]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp]
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 64]
    db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 80]
    movdqu xmm1, [esp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu [edi + 112], xmm0
    movdqu xmm0, [esp]
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 64]
    db $66, $0F, $73, $D8, $0C        // psrldq xmm0, $0C
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 16]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu xmm1, [esp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu [esp + 32], xmm0
    movdqu xmm0, [esp + 32]
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 64]
    db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 32]
    movdqu xmm1, [esp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 32], xmm0
    movdqu xmm0, [esp]
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 64]
    db $66, $0F, $73, $D8, $08        // psrldq xmm0, $08
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 64]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 32]
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 64]
    db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 80]
    movdqu xmm1, [esp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu [edi + 128], xmm0
    lea eax, [esp + 64]
    lea ebx, [esp + 32]
    movdqu xmm2, [ebx]
    db $66, $0F, $3A, $DF, $CA, $20   // aeskeygenassist xmm1, xmm2, $20
    movdqu [eax], xmm1
    movdqu xmm0, [esp + 64]
    db $66, $0F, $70, $C0, $55        // pshufd xmm0, xmm0, $55
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp]
    movdqu xmm1, [esp + 80]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp], xmm0
    movdqu xmm0, [esp + 64]
    movdqu xmm1, [esp]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu xmm1, [esp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu [esp], xmm0
    movdqu xmm0, [esp]
    movdqu [edi + 144], xmm0
    movdqu xmm0, [esp]
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 64]
    db $66, $0F, $73, $D8, $0C        // psrldq xmm0, $0C
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 32]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu xmm1, [esp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu [esp + 16], xmm0
    movdqu xmm0, [esp + 16]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 16]
    movdqu xmm1, [esp + 80]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 16], xmm0
    mov dword ptr [esp + 24], 0
    mov dword ptr [esp + 28], 0
    lea eax, [esp + 48]
    lea ebx, [esp + 16]
    movdqu xmm2, [ebx]
    db $66, $0F, $3A, $DF, $CA, $40   // aeskeygenassist xmm1, xmm2, $40
    movdqu [eax], xmm1
    movdqu xmm0, [esp + 48]
    db $66, $0F, $70, $C0, $55        // pshufd xmm0, xmm0, $55
    movdqu [esp + 48], xmm0
    movdqu xmm0, [esp]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp]
    movdqu xmm1, [esp + 80]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp], xmm0
    movdqu xmm0, [esp + 48]
    movdqu xmm1, [esp]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 48], xmm0
    movdqu xmm0, [esp]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu xmm1, [esp + 48]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu [esp], xmm0
    movdqu xmm0, [esp + 16]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp]
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 64]
    db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 80]
    movdqu xmm1, [esp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu [edi + 160], xmm0
    movdqu xmm0, [esp]
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 64]
    db $66, $0F, $73, $D8, $0C        // psrldq xmm0, $0C
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 16]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu xmm1, [esp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu [esp + 32], xmm0
    movdqu xmm0, [esp + 32]
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 64]
    db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 32]
    movdqu xmm1, [esp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 32], xmm0
    movdqu xmm0, [esp]
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 64]
    db $66, $0F, $73, $D8, $08        // psrldq xmm0, $08
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 64]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 32]
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 64]
    db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp + 80]
    movdqu xmm1, [esp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu [edi + 176], xmm0
    lea eax, [esp + 64]
    lea ebx, [esp + 32]
    movdqu xmm2, [ebx]
    db $66, $0F, $3A, $DF, $CA, $80   // aeskeygenassist xmm1, xmm2, $80
    movdqu [eax], xmm1
    movdqu xmm0, [esp + 64]
    db $66, $0F, $70, $C0, $55        // pshufd xmm0, xmm0, $55
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp]
    movdqu xmm1, [esp + 80]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp], xmm0
    movdqu xmm0, [esp + 64]
    movdqu xmm1, [esp]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 64], xmm0
    movdqu xmm0, [esp]
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu xmm1, [esp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [esp + 80], xmm0
    movdqu xmm0, [esp + 80]
    movdqu [esp], xmm0
    movdqu xmm0, [esp]
    movdqu [edi + 192], xmm0
    add esp, 96
    pop ebx
    pop edi
    pop esi
    pop ebx
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
    // AES-256 encryption round-key expansion, i386.
    // After SimdProc2Begin_i386: ebx = 32-byte key, esi = KeysOut (15 * 16 bytes).
    // Stack: s1,s2,t1,t2,w; edi = KeysOut. Saves edi, ebx (key ptr on stack).
    // AES-NI instructions are db-encoded for broad assembler compatibility.
    //
      push edi
      push ebx
      sub esp, 80
      mov edi, esi
      movdqu xmm0, [ebx]
      movdqu [esp], xmm0
      movdqu [edi], xmm0
      movdqu xmm0, [ebx + 16]
      movdqu [esp + 16], xmm0
      movdqu [edi + 16], xmm0

    // ---- iter 1a: rcon $01, update s1, K[2] ----
      lea eax, [esp + 48]
      lea ebx, [esp + 16]
      movdqu xmm2, [ebx]
      db $66, $0F, $3A, $DF, $CA, $01   // aeskeygenassist xmm1, xmm2, $01
      movdqu [eax], xmm1
      movdqu xmm0, [eax]
      db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
      movdqu [eax], xmm0
      movdqu xmm0, [esp]
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp]
      movdqu xmm1, [esp + 32]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp], xmm0
      movdqu xmm0, [esp + 48]
      movdqu xmm1, [esp]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp + 48], xmm0
      movdqu xmm0, [esp]
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      movdqu xmm1, [esp + 48]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      movdqu [esp], xmm0
      movdqu xmm0, [esp]
      movdqu [edi + 32], xmm0

    // ---- iter 1b: imm $00, update s2, K[3] ----
      lea eax, [esp + 64]
      lea ebx, [esp]
      movdqu xmm2, [ebx]
      db $66, $0F, $3A, $DF, $CA, $00   // aeskeygenassist xmm1, xmm2, $00
      movdqu [eax], xmm1
      movdqu xmm0, [eax]
      db $66, $0F, $70, $C0, $AA        // pshufd xmm0, xmm0, $AA
      movdqu [eax], xmm0
      movdqu xmm0, [esp + 16]
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 16]
      movdqu xmm1, [esp + 32]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp + 16], xmm0
      movdqu xmm0, [esp + 64]
      movdqu xmm1, [esp + 16]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp + 64], xmm0
      movdqu xmm0, [esp + 16]
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      movdqu xmm1, [esp + 64]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      movdqu [esp + 16], xmm0
      movdqu xmm0, [esp + 16]
      movdqu [edi + 48], xmm0

    // ---- iter 2a: rcon $02 ----
      lea eax, [esp + 48]
      lea ebx, [esp + 16]
      movdqu xmm2, [ebx]
      db $66, $0F, $3A, $DF, $CA, $02   // aeskeygenassist xmm1, xmm2, $02
      movdqu [eax], xmm1
      movdqu xmm0, [eax]
      db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
      movdqu [eax], xmm0
      movdqu xmm0, [esp]
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp]
      movdqu xmm1, [esp + 32]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp], xmm0
      movdqu xmm0, [esp + 48]
      movdqu xmm1, [esp]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp + 48], xmm0
      movdqu xmm0, [esp]
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      movdqu xmm1, [esp + 48]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      movdqu [esp], xmm0
      movdqu xmm0, [esp]
      movdqu [edi + 64], xmm0

    // ---- iter 2b: $00 ----
      lea eax, [esp + 64]
      lea ebx, [esp]
      movdqu xmm2, [ebx]
      db $66, $0F, $3A, $DF, $CA, $00   // aeskeygenassist xmm1, xmm2, $00
      movdqu [eax], xmm1
      movdqu xmm0, [eax]
      db $66, $0F, $70, $C0, $AA        // pshufd xmm0, xmm0, $AA
      movdqu [eax], xmm0
      movdqu xmm0, [esp + 16]
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 16]
      movdqu xmm1, [esp + 32]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp + 16], xmm0
      movdqu xmm0, [esp + 64]
      movdqu xmm1, [esp + 16]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp + 64], xmm0
      movdqu xmm0, [esp + 16]
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      movdqu xmm1, [esp + 64]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      movdqu [esp + 16], xmm0
      movdqu xmm0, [esp + 16]
      movdqu [edi + 80], xmm0

    // ---- iter 3a: rcon $04 ----
      lea eax, [esp + 48]
      lea ebx, [esp + 16]
      movdqu xmm2, [ebx]
      db $66, $0F, $3A, $DF, $CA, $04   // aeskeygenassist xmm1, xmm2, $04
      movdqu [eax], xmm1
      movdqu xmm0, [eax]
      db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
      movdqu [eax], xmm0
      movdqu xmm0, [esp]
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp]
      movdqu xmm1, [esp + 32]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp], xmm0
      movdqu xmm0, [esp + 48]
      movdqu xmm1, [esp]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp + 48], xmm0
      movdqu xmm0, [esp]
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      movdqu xmm1, [esp + 48]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      movdqu [esp], xmm0
      movdqu xmm0, [esp]
      movdqu [edi + 96], xmm0

    // ---- iter 3b ----
      lea eax, [esp + 64]
      lea ebx, [esp]
      movdqu xmm2, [ebx]
      db $66, $0F, $3A, $DF, $CA, $00   // aeskeygenassist xmm1, xmm2, $00
      movdqu [eax], xmm1
      movdqu xmm0, [eax]
      db $66, $0F, $70, $C0, $AA        // pshufd xmm0, xmm0, $AA
      movdqu [eax], xmm0
      movdqu xmm0, [esp + 16]
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 16]
      movdqu xmm1, [esp + 32]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp + 16], xmm0
      movdqu xmm0, [esp + 64]
      movdqu xmm1, [esp + 16]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp + 64], xmm0
      movdqu xmm0, [esp + 16]
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      movdqu xmm1, [esp + 64]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      movdqu [esp + 16], xmm0
      movdqu xmm0, [esp + 16]
      movdqu [edi + 112], xmm0

    // ---- iter 4a: rcon $08 ----
      lea eax, [esp + 48]
      lea ebx, [esp + 16]
      movdqu xmm2, [ebx]
      db $66, $0F, $3A, $DF, $CA, $08   // aeskeygenassist xmm1, xmm2, $08
      movdqu [eax], xmm1
      movdqu xmm0, [eax]
      db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
      movdqu [eax], xmm0
      movdqu xmm0, [esp]
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp]
      movdqu xmm1, [esp + 32]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp], xmm0
      movdqu xmm0, [esp + 48]
      movdqu xmm1, [esp]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp + 48], xmm0
      movdqu xmm0, [esp]
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      movdqu xmm1, [esp + 48]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      movdqu [esp], xmm0
      movdqu xmm0, [esp]
      movdqu [edi + 128], xmm0

    // ---- iter 4b ----
      lea eax, [esp + 64]
      lea ebx, [esp]
      movdqu xmm2, [ebx]
      db $66, $0F, $3A, $DF, $CA, $00   // aeskeygenassist xmm1, xmm2, $00
      movdqu [eax], xmm1
      movdqu xmm0, [eax]
      db $66, $0F, $70, $C0, $AA        // pshufd xmm0, xmm0, $AA
      movdqu [eax], xmm0
      movdqu xmm0, [esp + 16]
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 16]
      movdqu xmm1, [esp + 32]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp + 16], xmm0
      movdqu xmm0, [esp + 64]
      movdqu xmm1, [esp + 16]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp + 64], xmm0
      movdqu xmm0, [esp + 16]
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      movdqu xmm1, [esp + 64]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      movdqu [esp + 16], xmm0
      movdqu xmm0, [esp + 16]
      movdqu [edi + 144], xmm0

    // ---- iter 5a: rcon $10 ----
      lea eax, [esp + 48]
      lea ebx, [esp + 16]
      movdqu xmm2, [ebx]
      db $66, $0F, $3A, $DF, $CA, $10   // aeskeygenassist xmm1, xmm2, $10
      movdqu [eax], xmm1
      movdqu xmm0, [eax]
      db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
      movdqu [eax], xmm0
      movdqu xmm0, [esp]
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp]
      movdqu xmm1, [esp + 32]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp], xmm0
      movdqu xmm0, [esp + 48]
      movdqu xmm1, [esp]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp + 48], xmm0
      movdqu xmm0, [esp]
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      movdqu xmm1, [esp + 48]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      movdqu [esp], xmm0
      movdqu xmm0, [esp]
      movdqu [edi + 160], xmm0

    // ---- iter 5b ----
      lea eax, [esp + 64]
      lea ebx, [esp]
      movdqu xmm2, [ebx]
      db $66, $0F, $3A, $DF, $CA, $00   // aeskeygenassist xmm1, xmm2, $00
      movdqu [eax], xmm1
      movdqu xmm0, [eax]
      db $66, $0F, $70, $C0, $AA        // pshufd xmm0, xmm0, $AA
      movdqu [eax], xmm0
      movdqu xmm0, [esp + 16]
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 16]
      movdqu xmm1, [esp + 32]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp + 16], xmm0
      movdqu xmm0, [esp + 64]
      movdqu xmm1, [esp + 16]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp + 64], xmm0
      movdqu xmm0, [esp + 16]
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      movdqu xmm1, [esp + 64]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      movdqu [esp + 16], xmm0
      movdqu xmm0, [esp + 16]
      movdqu [edi + 176], xmm0

    // ---- iter 6a: rcon $20 ----
      lea eax, [esp + 48]
      lea ebx, [esp + 16]
      movdqu xmm2, [ebx]
      db $66, $0F, $3A, $DF, $CA, $20   // aeskeygenassist xmm1, xmm2, $20
      movdqu [eax], xmm1
      movdqu xmm0, [eax]
      db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
      movdqu [eax], xmm0
      movdqu xmm0, [esp]
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp]
      movdqu xmm1, [esp + 32]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp], xmm0
      movdqu xmm0, [esp + 48]
      movdqu xmm1, [esp]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp + 48], xmm0
      movdqu xmm0, [esp]
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      movdqu xmm1, [esp + 48]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      movdqu [esp], xmm0
      movdqu xmm0, [esp]
      movdqu [edi + 192], xmm0

    // ---- iter 6b ----
      lea eax, [esp + 64]
      lea ebx, [esp]
      movdqu xmm2, [ebx]
      db $66, $0F, $3A, $DF, $CA, $00   // aeskeygenassist xmm1, xmm2, $00
      movdqu [eax], xmm1
      movdqu xmm0, [eax]
      db $66, $0F, $70, $C0, $AA        // pshufd xmm0, xmm0, $AA
      movdqu [eax], xmm0
      movdqu xmm0, [esp + 16]
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 16]
      movdqu xmm1, [esp + 32]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp + 16], xmm0
      movdqu xmm0, [esp + 64]
      movdqu xmm1, [esp + 16]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp + 64], xmm0
      movdqu xmm0, [esp + 16]
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      movdqu xmm1, [esp + 64]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      movdqu [esp + 16], xmm0
      movdqu xmm0, [esp + 16]
      movdqu [edi + 208], xmm0

    // ---- iter 7a: rcon $40, K[14] only ----
      lea eax, [esp + 48]
      lea ebx, [esp + 16]
      movdqu xmm2, [ebx]
      db $66, $0F, $3A, $DF, $CA, $40   // aeskeygenassist xmm1, xmm2, $40
      movdqu [eax], xmm1
      movdqu xmm0, [eax]
      db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
      movdqu [eax], xmm0
      movdqu xmm0, [esp]
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp]
      movdqu xmm1, [esp + 32]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp], xmm0
      movdqu xmm0, [esp + 48]
      movdqu xmm1, [esp]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp + 48], xmm0
      movdqu xmm0, [esp]
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      movdqu xmm1, [esp + 48]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [esp + 32], xmm0
      movdqu xmm0, [esp + 32]
      movdqu [esp], xmm0
      movdqu xmm0, [esp]
      movdqu [edi + 224], xmm0

      add esp, 80
      pop ebx
      pop edi
      pop esi
      pop ebx
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

