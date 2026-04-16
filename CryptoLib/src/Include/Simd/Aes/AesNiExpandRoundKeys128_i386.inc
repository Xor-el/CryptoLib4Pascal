// AES-128 encryption round-key expansion, i386.
// After SimdProc2Begin_i386: ebx = 16-byte key, esi = KeysOut (11 * 16 bytes).
// Stack: Ls1, Lt1, Lw; edi = KeysOut. Saves edi, ebx (key ptr on stack).
// Db-encoded AES-NI / SSE2 (broad assembler support).
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
