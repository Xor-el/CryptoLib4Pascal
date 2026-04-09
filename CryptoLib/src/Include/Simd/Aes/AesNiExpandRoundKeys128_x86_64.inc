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
