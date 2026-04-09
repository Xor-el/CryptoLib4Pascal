// AES-192 encryption round-key expansion, i386.
// Expects: eax = 24-byte key, edx = KeysOut (13 * 16 bytes); register calling convention.
// Stack: S1,S2,S3,T1,T2,W; edi = KeysOut. Saves edi, ebx.
// Db-encoded AES-NI / SSE2 (broad assembler support).
//
  push edi
  push ebx
  sub esp, 96
  mov edi, edx
  movdqu xmm0, [eax]
  movdqu [esp], xmm0
  movdqu [edi], xmm0
  pxor xmm0, xmm0
  movdqu [esp + 16], xmm0
  db $F3, $0F, $7E, $40, $10   // movq xmm0, qword ptr [eax + 16]
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
