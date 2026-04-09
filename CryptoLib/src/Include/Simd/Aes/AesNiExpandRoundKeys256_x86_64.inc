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
