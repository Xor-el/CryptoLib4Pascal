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
