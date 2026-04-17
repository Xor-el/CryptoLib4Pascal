// AesNiExpandRoundKeys x86 64 (merged key sizes)
// Define exactly one of: CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256
// before including this file (see ClpAesEngineX86).

{$IFDEF CRYPTOLIB_AESNI_KEY128}
// AES-128 encryption round-key expansion, x86-64.
// Expects MS x64 ABI: rcx = 16-byte key, rdx = KeysOut (11 * 16 bytes).
// Stack: Ls1, Lt1, Lw; r12 = KeysOut. Saves r12, rbx.
// Db-encoded AES-NI / SSE2 (broad assembler support).
//
  push r12
  push rbx
  sub rsp, 48
  mov r12, rdx
  movdqu xmm0, [rcx]
  movdqu [rsp], xmm0
  movdqu [r12], xmm0

// ----- round 0 -> K[1], rcon $01 -----
  lea rcx, [rsp + 16]
  lea rdx, [rsp]
  movdqu xmm2, [rdx]
  db $66, $0F, $3A, $DF, $CA, $01   // aeskeygenassist xmm1, xmm2, $01
  movdqu [rcx], xmm1
  movdqu xmm0, [rcx]
  db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
  movdqu [rcx], xmm0
  movdqu xmm0, [rsp]
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp]
  movdqu xmm1, [rsp + 32]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rsp], xmm0
  movdqu xmm0, [rsp + 16]
  movdqu xmm1, [rsp]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rsp + 16], xmm0
  movdqu xmm0, [rsp]
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  movdqu xmm1, [rsp + 16]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  movdqu [rsp], xmm0
  movdqu xmm0, [rsp]
  movdqu [r12 + 16], xmm0

// ----- round 1, rcon $02 -----
  lea rcx, [rsp + 16]
  lea rdx, [rsp]
  movdqu xmm2, [rdx]
  db $66, $0F, $3A, $DF, $CA, $02   // aeskeygenassist xmm1, xmm2, $02
  movdqu [rcx], xmm1
  movdqu xmm0, [rcx]
  db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
  movdqu [rcx], xmm0
  movdqu xmm0, [rsp]
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp]
  movdqu xmm1, [rsp + 32]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rsp], xmm0
  movdqu xmm0, [rsp + 16]
  movdqu xmm1, [rsp]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rsp + 16], xmm0
  movdqu xmm0, [rsp]
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  movdqu xmm1, [rsp + 16]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  movdqu [rsp], xmm0
  movdqu xmm0, [rsp]
  movdqu [r12 + 32], xmm0

// ----- round 2, rcon $04 -----
  lea rcx, [rsp + 16]
  lea rdx, [rsp]
  movdqu xmm2, [rdx]
  db $66, $0F, $3A, $DF, $CA, $04   // aeskeygenassist xmm1, xmm2, $04
  movdqu [rcx], xmm1
  movdqu xmm0, [rcx]
  db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
  movdqu [rcx], xmm0
  movdqu xmm0, [rsp]
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp]
  movdqu xmm1, [rsp + 32]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rsp], xmm0
  movdqu xmm0, [rsp + 16]
  movdqu xmm1, [rsp]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rsp + 16], xmm0
  movdqu xmm0, [rsp]
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  movdqu xmm1, [rsp + 16]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  movdqu [rsp], xmm0
  movdqu xmm0, [rsp]
  movdqu [r12 + 48], xmm0

// ----- round 3, rcon $08 -----
  lea rcx, [rsp + 16]
  lea rdx, [rsp]
  movdqu xmm2, [rdx]
  db $66, $0F, $3A, $DF, $CA, $08   // aeskeygenassist xmm1, xmm2, $08
  movdqu [rcx], xmm1
  movdqu xmm0, [rcx]
  db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
  movdqu [rcx], xmm0
  movdqu xmm0, [rsp]
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp]
  movdqu xmm1, [rsp + 32]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rsp], xmm0
  movdqu xmm0, [rsp + 16]
  movdqu xmm1, [rsp]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rsp + 16], xmm0
  movdqu xmm0, [rsp]
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  movdqu xmm1, [rsp + 16]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  movdqu [rsp], xmm0
  movdqu xmm0, [rsp]
  movdqu [r12 + 64], xmm0

// ----- round 4, rcon $10 -----
  lea rcx, [rsp + 16]
  lea rdx, [rsp]
  movdqu xmm2, [rdx]
  db $66, $0F, $3A, $DF, $CA, $10   // aeskeygenassist xmm1, xmm2, $10
  movdqu [rcx], xmm1
  movdqu xmm0, [rcx]
  db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
  movdqu [rcx], xmm0
  movdqu xmm0, [rsp]
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp]
  movdqu xmm1, [rsp + 32]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rsp], xmm0
  movdqu xmm0, [rsp + 16]
  movdqu xmm1, [rsp]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rsp + 16], xmm0
  movdqu xmm0, [rsp]
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  movdqu xmm1, [rsp + 16]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  movdqu [rsp], xmm0
  movdqu xmm0, [rsp]
  movdqu [r12 + 80], xmm0

// ----- round 5, rcon $20 -----
  lea rcx, [rsp + 16]
  lea rdx, [rsp]
  movdqu xmm2, [rdx]
  db $66, $0F, $3A, $DF, $CA, $20   // aeskeygenassist xmm1, xmm2, $20
  movdqu [rcx], xmm1
  movdqu xmm0, [rcx]
  db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
  movdqu [rcx], xmm0
  movdqu xmm0, [rsp]
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp]
  movdqu xmm1, [rsp + 32]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rsp], xmm0
  movdqu xmm0, [rsp + 16]
  movdqu xmm1, [rsp]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rsp + 16], xmm0
  movdqu xmm0, [rsp]
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  movdqu xmm1, [rsp + 16]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  movdqu [rsp], xmm0
  movdqu xmm0, [rsp]
  movdqu [r12 + 96], xmm0

// ----- round 6, rcon $40 -----
  lea rcx, [rsp + 16]
  lea rdx, [rsp]
  movdqu xmm2, [rdx]
  db $66, $0F, $3A, $DF, $CA, $40   // aeskeygenassist xmm1, xmm2, $40
  movdqu [rcx], xmm1
  movdqu xmm0, [rcx]
  db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
  movdqu [rcx], xmm0
  movdqu xmm0, [rsp]
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp]
  movdqu xmm1, [rsp + 32]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rsp], xmm0
  movdqu xmm0, [rsp + 16]
  movdqu xmm1, [rsp]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rsp + 16], xmm0
  movdqu xmm0, [rsp]
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  movdqu xmm1, [rsp + 16]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  movdqu [rsp], xmm0
  movdqu xmm0, [rsp]
  movdqu [r12 + 112], xmm0

// ----- round 7, rcon $80 -----
  lea rcx, [rsp + 16]
  lea rdx, [rsp]
  movdqu xmm2, [rdx]
  db $66, $0F, $3A, $DF, $CA, $80   // aeskeygenassist xmm1, xmm2, $80
  movdqu [rcx], xmm1
  movdqu xmm0, [rcx]
  db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
  movdqu [rcx], xmm0
  movdqu xmm0, [rsp]
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp]
  movdqu xmm1, [rsp + 32]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rsp], xmm0
  movdqu xmm0, [rsp + 16]
  movdqu xmm1, [rsp]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rsp + 16], xmm0
  movdqu xmm0, [rsp]
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  movdqu xmm1, [rsp + 16]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  movdqu [rsp], xmm0
  movdqu xmm0, [rsp]
  movdqu [r12 + 128], xmm0

// ----- round 8, rcon $1B -----
  lea rcx, [rsp + 16]
  lea rdx, [rsp]
  movdqu xmm2, [rdx]
  db $66, $0F, $3A, $DF, $CA, $1B   // aeskeygenassist xmm1, xmm2, $1B
  movdqu [rcx], xmm1
  movdqu xmm0, [rcx]
  db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
  movdqu [rcx], xmm0
  movdqu xmm0, [rsp]
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp]
  movdqu xmm1, [rsp + 32]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rsp], xmm0
  movdqu xmm0, [rsp + 16]
  movdqu xmm1, [rsp]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rsp + 16], xmm0
  movdqu xmm0, [rsp]
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  movdqu xmm1, [rsp + 16]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  movdqu [rsp], xmm0
  movdqu xmm0, [rsp]
  movdqu [r12 + 144], xmm0

// ----- round 9, rcon $36 -> K[10] -----
  lea rcx, [rsp + 16]
  lea rdx, [rsp]
  movdqu xmm2, [rdx]
  db $66, $0F, $3A, $DF, $CA, $36   // aeskeygenassist xmm1, xmm2, $36
  movdqu [rcx], xmm1
  movdqu xmm0, [rcx]
  db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
  movdqu [rcx], xmm0
  movdqu xmm0, [rsp]
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp]
  movdqu xmm1, [rsp + 32]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rsp], xmm0
  movdqu xmm0, [rsp + 16]
  movdqu xmm1, [rsp]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rsp + 16], xmm0
  movdqu xmm0, [rsp]
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  movdqu xmm1, [rsp + 16]
  db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
  movdqu [rsp + 32], xmm0
  movdqu xmm0, [rsp + 32]
  movdqu [rsp], xmm0
  movdqu xmm0, [rsp]
  movdqu [r12 + 160], xmm0

  add rsp, 48
  pop rbx
  pop r12
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
  // AES-192 encryption round-key expansion, x86-64.
  // Expects MS x64 ABI: rcx = 24-byte key, rdx = KeysOut (13 * 16 bytes).
  // Stack: S1,S2,S3,T1,T2,W; r12 = KeysOut. Saves r12, rbx.
  // Db-encoded AES-NI / SSE2 (broad assembler support).
  //
    push r12
    push rbx
    sub rsp, 96
    mov r12, rdx
    movdqu xmm0, [rcx]
    movdqu [rsp], xmm0
    movdqu [r12], xmm0
    pxor xmm0, xmm0
    movdqu [rsp + 16], xmm0
    movq xmm0, qword ptr [rcx + 16]
    movdqu [rsp + 16], xmm0

    lea rcx, [rsp + 48]
    lea rdx, [rsp + 16]
    movdqu xmm2, [rdx]
    db $66, $0F, $3A, $DF, $CA, $01   // aeskeygenassist xmm1, xmm2, $01
    movdqu [rcx], xmm1
    movdqu xmm0, [rsp + 48]
    db $66, $0F, $70, $C0, $55        // pshufd xmm0, xmm0, $55
    movdqu [rsp + 48], xmm0
    movdqu xmm0, [rsp]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp]
    movdqu xmm1, [rsp + 80]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp], xmm0
    movdqu xmm0, [rsp + 48]
    movdqu xmm1, [rsp]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 48], xmm0
    movdqu xmm0, [rsp]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu xmm1, [rsp + 48]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu [rsp], xmm0
    movdqu xmm0, [rsp + 16]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp]
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 64]
    db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu xmm1, [rsp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu [r12 + 16], xmm0
    movdqu xmm0, [rsp]
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 64]
    db $66, $0F, $73, $D8, $0C        // psrldq xmm0, $0C
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 16]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu xmm1, [rsp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu [rsp + 32], xmm0
    movdqu xmm0, [rsp + 32]
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 64]
    db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 32]
    movdqu xmm1, [rsp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 32], xmm0
    movdqu xmm0, [rsp]
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 64]
    db $66, $0F, $73, $D8, $08        // psrldq xmm0, $08
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 64]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 32]
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 64]
    db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu xmm1, [rsp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu [r12 + 32], xmm0
    lea rcx, [rsp + 64]
    lea rdx, [rsp + 32]
    movdqu xmm2, [rdx]
    db $66, $0F, $3A, $DF, $CA, $02   // aeskeygenassist xmm1, xmm2, $02
    movdqu [rcx], xmm1
    movdqu xmm0, [rsp + 64]
    db $66, $0F, $70, $C0, $55        // pshufd xmm0, xmm0, $55
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp]
    movdqu xmm1, [rsp + 80]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp], xmm0
    movdqu xmm0, [rsp + 64]
    movdqu xmm1, [rsp]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu xmm1, [rsp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu [rsp], xmm0
    movdqu xmm0, [rsp]
    movdqu [r12 + 48], xmm0
    movdqu xmm0, [rsp]
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 64]
    db $66, $0F, $73, $D8, $0C        // psrldq xmm0, $0C
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 32]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu xmm1, [rsp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu [rsp + 16], xmm0
    movdqu xmm0, [rsp + 16]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 16]
    movdqu xmm1, [rsp + 80]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 16], xmm0
    mov qword ptr [rsp + 24], 0
    lea rcx, [rsp + 48]
    lea rdx, [rsp + 16]
    movdqu xmm2, [rdx]
    db $66, $0F, $3A, $DF, $CA, $04   // aeskeygenassist xmm1, xmm2, $04
    movdqu [rcx], xmm1
    movdqu xmm0, [rsp + 48]
    db $66, $0F, $70, $C0, $55        // pshufd xmm0, xmm0, $55
    movdqu [rsp + 48], xmm0
    movdqu xmm0, [rsp]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp]
    movdqu xmm1, [rsp + 80]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp], xmm0
    movdqu xmm0, [rsp + 48]
    movdqu xmm1, [rsp]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 48], xmm0
    movdqu xmm0, [rsp]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu xmm1, [rsp + 48]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu [rsp], xmm0
    movdqu xmm0, [rsp + 16]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp]
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 64]
    db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu xmm1, [rsp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu [r12 + 64], xmm0
    movdqu xmm0, [rsp]
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 64]
    db $66, $0F, $73, $D8, $0C        // psrldq xmm0, $0C
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 16]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu xmm1, [rsp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu [rsp + 32], xmm0
    movdqu xmm0, [rsp + 32]
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 64]
    db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 32]
    movdqu xmm1, [rsp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 32], xmm0
    movdqu xmm0, [rsp]
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 64]
    db $66, $0F, $73, $D8, $08        // psrldq xmm0, $08
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 64]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 32]
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 64]
    db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu xmm1, [rsp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu [r12 + 80], xmm0
    lea rcx, [rsp + 64]
    lea rdx, [rsp + 32]
    movdqu xmm2, [rdx]
    db $66, $0F, $3A, $DF, $CA, $08   // aeskeygenassist xmm1, xmm2, $08
    movdqu [rcx], xmm1
    movdqu xmm0, [rsp + 64]
    db $66, $0F, $70, $C0, $55        // pshufd xmm0, xmm0, $55
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp]
    movdqu xmm1, [rsp + 80]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp], xmm0
    movdqu xmm0, [rsp + 64]
    movdqu xmm1, [rsp]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu xmm1, [rsp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu [rsp], xmm0
    movdqu xmm0, [rsp]
    movdqu [r12 + 96], xmm0
    movdqu xmm0, [rsp]
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 64]
    db $66, $0F, $73, $D8, $0C        // psrldq xmm0, $0C
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 32]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu xmm1, [rsp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu [rsp + 16], xmm0
    movdqu xmm0, [rsp + 16]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 16]
    movdqu xmm1, [rsp + 80]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 16], xmm0
    mov qword ptr [rsp + 24], 0
    lea rcx, [rsp + 48]
    lea rdx, [rsp + 16]
    movdqu xmm2, [rdx]
    db $66, $0F, $3A, $DF, $CA, $10   // aeskeygenassist xmm1, xmm2, $10
    movdqu [rcx], xmm1
    movdqu xmm0, [rsp + 48]
    db $66, $0F, $70, $C0, $55        // pshufd xmm0, xmm0, $55
    movdqu [rsp + 48], xmm0
    movdqu xmm0, [rsp]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp]
    movdqu xmm1, [rsp + 80]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp], xmm0
    movdqu xmm0, [rsp + 48]
    movdqu xmm1, [rsp]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 48], xmm0
    movdqu xmm0, [rsp]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu xmm1, [rsp + 48]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu [rsp], xmm0
    movdqu xmm0, [rsp + 16]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp]
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 64]
    db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu xmm1, [rsp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu [r12 + 112], xmm0
    movdqu xmm0, [rsp]
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 64]
    db $66, $0F, $73, $D8, $0C        // psrldq xmm0, $0C
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 16]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu xmm1, [rsp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu [rsp + 32], xmm0
    movdqu xmm0, [rsp + 32]
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 64]
    db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 32]
    movdqu xmm1, [rsp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 32], xmm0
    movdqu xmm0, [rsp]
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 64]
    db $66, $0F, $73, $D8, $08        // psrldq xmm0, $08
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 64]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 32]
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 64]
    db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu xmm1, [rsp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu [r12 + 128], xmm0
    lea rcx, [rsp + 64]
    lea rdx, [rsp + 32]
    movdqu xmm2, [rdx]
    db $66, $0F, $3A, $DF, $CA, $20   // aeskeygenassist xmm1, xmm2, $20
    movdqu [rcx], xmm1
    movdqu xmm0, [rsp + 64]
    db $66, $0F, $70, $C0, $55        // pshufd xmm0, xmm0, $55
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp]
    movdqu xmm1, [rsp + 80]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp], xmm0
    movdqu xmm0, [rsp + 64]
    movdqu xmm1, [rsp]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu xmm1, [rsp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu [rsp], xmm0
    movdqu xmm0, [rsp]
    movdqu [r12 + 144], xmm0
    movdqu xmm0, [rsp]
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 64]
    db $66, $0F, $73, $D8, $0C        // psrldq xmm0, $0C
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 32]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu xmm1, [rsp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu [rsp + 16], xmm0
    movdqu xmm0, [rsp + 16]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 16]
    movdqu xmm1, [rsp + 80]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 16], xmm0
    mov qword ptr [rsp + 24], 0
    lea rcx, [rsp + 48]
    lea rdx, [rsp + 16]
    movdqu xmm2, [rdx]
    db $66, $0F, $3A, $DF, $CA, $40   // aeskeygenassist xmm1, xmm2, $40
    movdqu [rcx], xmm1
    movdqu xmm0, [rsp + 48]
    db $66, $0F, $70, $C0, $55        // pshufd xmm0, xmm0, $55
    movdqu [rsp + 48], xmm0
    movdqu xmm0, [rsp]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp]
    movdqu xmm1, [rsp + 80]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp], xmm0
    movdqu xmm0, [rsp + 48]
    movdqu xmm1, [rsp]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 48], xmm0
    movdqu xmm0, [rsp]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu xmm1, [rsp + 48]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu [rsp], xmm0
    movdqu xmm0, [rsp + 16]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp]
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 64]
    db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu xmm1, [rsp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu [r12 + 160], xmm0
    movdqu xmm0, [rsp]
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 64]
    db $66, $0F, $73, $D8, $0C        // psrldq xmm0, $0C
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 16]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu xmm1, [rsp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu [rsp + 32], xmm0
    movdqu xmm0, [rsp + 32]
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 64]
    db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 32]
    movdqu xmm1, [rsp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 32], xmm0
    movdqu xmm0, [rsp]
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 64]
    db $66, $0F, $73, $D8, $08        // psrldq xmm0, $08
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 64]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 32]
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 64]
    db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu xmm1, [rsp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu [r12 + 176], xmm0
    lea rcx, [rsp + 64]
    lea rdx, [rsp + 32]
    movdqu xmm2, [rdx]
    db $66, $0F, $3A, $DF, $CA, $80   // aeskeygenassist xmm1, xmm2, $80
    movdqu [rcx], xmm1
    movdqu xmm0, [rsp + 64]
    db $66, $0F, $70, $C0, $55        // pshufd xmm0, xmm0, $55
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp]
    movdqu xmm1, [rsp + 80]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp], xmm0
    movdqu xmm0, [rsp + 64]
    movdqu xmm1, [rsp]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 64], xmm0
    movdqu xmm0, [rsp]
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu xmm1, [rsp + 64]
    db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
    movdqu [rsp + 80], xmm0
    movdqu xmm0, [rsp + 80]
    movdqu [rsp], xmm0
    movdqu xmm0, [rsp]
    movdqu [r12 + 192], xmm0
    add rsp, 96
    pop rbx
    pop r12
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
    // AES-256 encryption round-key expansion, x86-64.
    // Expects MS x64 ABI: rcx = 32-byte key, rdx = KeysOut (15 * 16 bytes).
    // Stack: s1,s2,t1,t2,w; r12 = KeysOut. Saves r12, rbx.
    // Db-encoded AES-NI / SSE2 (broad assembler support).
    //
      push r12
      push rbx
      sub rsp, 80
      mov r12, rdx
      movdqu xmm0, [rcx]
      movdqu [rsp], xmm0
      movdqu [r12], xmm0
      movdqu xmm0, [rcx + 16]
      movdqu [rsp + 16], xmm0
      movdqu [r12 + 16], xmm0

    // ---- iter 1a: rcon $01, update s1, K[2] ----
      lea rcx, [rsp + 48]
      lea rdx, [rsp + 16]
      movdqu xmm2, [rdx]
      db $66, $0F, $3A, $DF, $CA, $01   // aeskeygenassist xmm1, xmm2, $01
      movdqu [rcx], xmm1
      movdqu xmm0, [rcx]
      db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
      movdqu [rcx], xmm0
      movdqu xmm0, [rsp]
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp]
      movdqu xmm1, [rsp + 32]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp], xmm0
      movdqu xmm0, [rsp + 48]
      movdqu xmm1, [rsp]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp + 48], xmm0
      movdqu xmm0, [rsp]
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      movdqu xmm1, [rsp + 48]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      movdqu [rsp], xmm0
      movdqu xmm0, [rsp]
      movdqu [r12 + 32], xmm0

    // ---- iter 1b: imm $00, update s2, K[3] ----
      lea rcx, [rsp + 64]
      lea rdx, [rsp]
      movdqu xmm2, [rdx]
      db $66, $0F, $3A, $DF, $CA, $00   // aeskeygenassist xmm1, xmm2, $00
      movdqu [rcx], xmm1
      movdqu xmm0, [rcx]
      db $66, $0F, $70, $C0, $AA        // pshufd xmm0, xmm0, $AA
      movdqu [rcx], xmm0
      movdqu xmm0, [rsp + 16]
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 16]
      movdqu xmm1, [rsp + 32]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp + 16], xmm0
      movdqu xmm0, [rsp + 64]
      movdqu xmm1, [rsp + 16]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp + 64], xmm0
      movdqu xmm0, [rsp + 16]
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      movdqu xmm1, [rsp + 64]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      movdqu [rsp + 16], xmm0
      movdqu xmm0, [rsp + 16]
      movdqu [r12 + 48], xmm0

    // ---- iter 2a: rcon $02 ----
      lea rcx, [rsp + 48]
      lea rdx, [rsp + 16]
      movdqu xmm2, [rdx]
      db $66, $0F, $3A, $DF, $CA, $02   // aeskeygenassist xmm1, xmm2, $02
      movdqu [rcx], xmm1
      movdqu xmm0, [rcx]
      db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
      movdqu [rcx], xmm0
      movdqu xmm0, [rsp]
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp]
      movdqu xmm1, [rsp + 32]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp], xmm0
      movdqu xmm0, [rsp + 48]
      movdqu xmm1, [rsp]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp + 48], xmm0
      movdqu xmm0, [rsp]
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      movdqu xmm1, [rsp + 48]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      movdqu [rsp], xmm0
      movdqu xmm0, [rsp]
      movdqu [r12 + 64], xmm0

    // ---- iter 2b: $00 ----
      lea rcx, [rsp + 64]
      lea rdx, [rsp]
      movdqu xmm2, [rdx]
      db $66, $0F, $3A, $DF, $CA, $00   // aeskeygenassist xmm1, xmm2, $00
      movdqu [rcx], xmm1
      movdqu xmm0, [rcx]
      db $66, $0F, $70, $C0, $AA        // pshufd xmm0, xmm0, $AA
      movdqu [rcx], xmm0
      movdqu xmm0, [rsp + 16]
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 16]
      movdqu xmm1, [rsp + 32]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp + 16], xmm0
      movdqu xmm0, [rsp + 64]
      movdqu xmm1, [rsp + 16]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp + 64], xmm0
      movdqu xmm0, [rsp + 16]
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      movdqu xmm1, [rsp + 64]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      movdqu [rsp + 16], xmm0
      movdqu xmm0, [rsp + 16]
      movdqu [r12 + 80], xmm0

    // ---- iter 3a: rcon $04 ----
      lea rcx, [rsp + 48]
      lea rdx, [rsp + 16]
      movdqu xmm2, [rdx]
      db $66, $0F, $3A, $DF, $CA, $04   // aeskeygenassist xmm1, xmm2, $04
      movdqu [rcx], xmm1
      movdqu xmm0, [rcx]
      db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
      movdqu [rcx], xmm0
      movdqu xmm0, [rsp]
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp]
      movdqu xmm1, [rsp + 32]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp], xmm0
      movdqu xmm0, [rsp + 48]
      movdqu xmm1, [rsp]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp + 48], xmm0
      movdqu xmm0, [rsp]
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      movdqu xmm1, [rsp + 48]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      movdqu [rsp], xmm0
      movdqu xmm0, [rsp]
      movdqu [r12 + 96], xmm0

    // ---- iter 3b ----
      lea rcx, [rsp + 64]
      lea rdx, [rsp]
      movdqu xmm2, [rdx]
      db $66, $0F, $3A, $DF, $CA, $00   // aeskeygenassist xmm1, xmm2, $00
      movdqu [rcx], xmm1
      movdqu xmm0, [rcx]
      db $66, $0F, $70, $C0, $AA        // pshufd xmm0, xmm0, $AA
      movdqu [rcx], xmm0
      movdqu xmm0, [rsp + 16]
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 16]
      movdqu xmm1, [rsp + 32]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp + 16], xmm0
      movdqu xmm0, [rsp + 64]
      movdqu xmm1, [rsp + 16]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp + 64], xmm0
      movdqu xmm0, [rsp + 16]
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      movdqu xmm1, [rsp + 64]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      movdqu [rsp + 16], xmm0
      movdqu xmm0, [rsp + 16]
      movdqu [r12 + 112], xmm0

    // ---- iter 4a: rcon $08 ----
      lea rcx, [rsp + 48]
      lea rdx, [rsp + 16]
      movdqu xmm2, [rdx]
      db $66, $0F, $3A, $DF, $CA, $08   // aeskeygenassist xmm1, xmm2, $08
      movdqu [rcx], xmm1
      movdqu xmm0, [rcx]
      db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
      movdqu [rcx], xmm0
      movdqu xmm0, [rsp]
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp]
      movdqu xmm1, [rsp + 32]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp], xmm0
      movdqu xmm0, [rsp + 48]
      movdqu xmm1, [rsp]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp + 48], xmm0
      movdqu xmm0, [rsp]
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      movdqu xmm1, [rsp + 48]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      movdqu [rsp], xmm0
      movdqu xmm0, [rsp]
      movdqu [r12 + 128], xmm0

    // ---- iter 4b ----
      lea rcx, [rsp + 64]
      lea rdx, [rsp]
      movdqu xmm2, [rdx]
      db $66, $0F, $3A, $DF, $CA, $00   // aeskeygenassist xmm1, xmm2, $00
      movdqu [rcx], xmm1
      movdqu xmm0, [rcx]
      db $66, $0F, $70, $C0, $AA        // pshufd xmm0, xmm0, $AA
      movdqu [rcx], xmm0
      movdqu xmm0, [rsp + 16]
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 16]
      movdqu xmm1, [rsp + 32]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp + 16], xmm0
      movdqu xmm0, [rsp + 64]
      movdqu xmm1, [rsp + 16]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp + 64], xmm0
      movdqu xmm0, [rsp + 16]
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      movdqu xmm1, [rsp + 64]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      movdqu [rsp + 16], xmm0
      movdqu xmm0, [rsp + 16]
      movdqu [r12 + 144], xmm0

    // ---- iter 5a: rcon $10 ----
      lea rcx, [rsp + 48]
      lea rdx, [rsp + 16]
      movdqu xmm2, [rdx]
      db $66, $0F, $3A, $DF, $CA, $10   // aeskeygenassist xmm1, xmm2, $10
      movdqu [rcx], xmm1
      movdqu xmm0, [rcx]
      db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
      movdqu [rcx], xmm0
      movdqu xmm0, [rsp]
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp]
      movdqu xmm1, [rsp + 32]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp], xmm0
      movdqu xmm0, [rsp + 48]
      movdqu xmm1, [rsp]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp + 48], xmm0
      movdqu xmm0, [rsp]
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      movdqu xmm1, [rsp + 48]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      movdqu [rsp], xmm0
      movdqu xmm0, [rsp]
      movdqu [r12 + 160], xmm0

    // ---- iter 5b ----
      lea rcx, [rsp + 64]
      lea rdx, [rsp]
      movdqu xmm2, [rdx]
      db $66, $0F, $3A, $DF, $CA, $00   // aeskeygenassist xmm1, xmm2, $00
      movdqu [rcx], xmm1
      movdqu xmm0, [rcx]
      db $66, $0F, $70, $C0, $AA        // pshufd xmm0, xmm0, $AA
      movdqu [rcx], xmm0
      movdqu xmm0, [rsp + 16]
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 16]
      movdqu xmm1, [rsp + 32]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp + 16], xmm0
      movdqu xmm0, [rsp + 64]
      movdqu xmm1, [rsp + 16]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp + 64], xmm0
      movdqu xmm0, [rsp + 16]
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      movdqu xmm1, [rsp + 64]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      movdqu [rsp + 16], xmm0
      movdqu xmm0, [rsp + 16]
      movdqu [r12 + 176], xmm0

    // ---- iter 6a: rcon $20 ----
      lea rcx, [rsp + 48]
      lea rdx, [rsp + 16]
      movdqu xmm2, [rdx]
      db $66, $0F, $3A, $DF, $CA, $20   // aeskeygenassist xmm1, xmm2, $20
      movdqu [rcx], xmm1
      movdqu xmm0, [rcx]
      db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
      movdqu [rcx], xmm0
      movdqu xmm0, [rsp]
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp]
      movdqu xmm1, [rsp + 32]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp], xmm0
      movdqu xmm0, [rsp + 48]
      movdqu xmm1, [rsp]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp + 48], xmm0
      movdqu xmm0, [rsp]
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      movdqu xmm1, [rsp + 48]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      movdqu [rsp], xmm0
      movdqu xmm0, [rsp]
      movdqu [r12 + 192], xmm0

    // ---- iter 6b ----
      lea rcx, [rsp + 64]
      lea rdx, [rsp]
      movdqu xmm2, [rdx]
      db $66, $0F, $3A, $DF, $CA, $00   // aeskeygenassist xmm1, xmm2, $00
      movdqu [rcx], xmm1
      movdqu xmm0, [rcx]
      db $66, $0F, $70, $C0, $AA        // pshufd xmm0, xmm0, $AA
      movdqu [rcx], xmm0
      movdqu xmm0, [rsp + 16]
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 16]
      movdqu xmm1, [rsp + 32]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp + 16], xmm0
      movdqu xmm0, [rsp + 64]
      movdqu xmm1, [rsp + 16]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp + 64], xmm0
      movdqu xmm0, [rsp + 16]
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      movdqu xmm1, [rsp + 64]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      movdqu [rsp + 16], xmm0
      movdqu xmm0, [rsp + 16]
      movdqu [r12 + 208], xmm0

    // ---- iter 7a: rcon $40, K[14] only ----
      lea rcx, [rsp + 48]
      lea rdx, [rsp + 16]
      movdqu xmm2, [rdx]
      db $66, $0F, $3A, $DF, $CA, $40   // aeskeygenassist xmm1, xmm2, $40
      movdqu [rcx], xmm1
      movdqu xmm0, [rcx]
      db $66, $0F, $70, $C0, $FF        // pshufd xmm0, xmm0, $FF
      movdqu [rcx], xmm0
      movdqu xmm0, [rsp]
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      db $66, $0F, $73, $F8, $08        // pslldq xmm0, $08
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp]
      movdqu xmm1, [rsp + 32]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp], xmm0
      movdqu xmm0, [rsp + 48]
      movdqu xmm1, [rsp]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp + 48], xmm0
      movdqu xmm0, [rsp]
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      db $66, $0F, $73, $F8, $04        // pslldq xmm0, $04
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      movdqu xmm1, [rsp + 48]
      db $66, $0F, $EF, $C1              // pxor xmm0, xmm1
      movdqu [rsp + 32], xmm0
      movdqu xmm0, [rsp + 32]
      movdqu [rsp], xmm0
      movdqu xmm0, [rsp]
      movdqu [r12 + 224], xmm0

      add rsp, 80
      pop rbx
      pop r12
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}

