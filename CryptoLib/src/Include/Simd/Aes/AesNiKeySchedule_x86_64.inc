// AES-NI key-schedule kernel, merged expansion + decrypt-prep, merged key sizes (x86-64).
// -------------------------------------------------------------------
//
// Expansion: register-resident aeskeygenassist ladder producing the
// N_R + 1 round keys (16 bytes each) per the AES-128 / 192 / 256
// schedules; N_R = 10 / 12 / 14. Decrypt-prep: aesimc on the middle
// round keys (1..N_R - 1) in place, then reverses the key order to
// produce a schedule suitable for aesdec / aesdeclast.
//
// Variant selection:
//   CRYPTOLIB_AESNI_KEYSCHEDULE_INVERT  -> decrypt-prep; else expansion
//   with exactly one of CRYPTOLIB_AESNI_KEY128 / KEY192 / KEY256.
//
// Entry (after ClpSimdProc2Begin_x86_64.inc):
//   expansion:    rcx = user key (16 / 24 / 32 bytes),
//                 rdx = KeysOut (16 * (N_R + 1) bytes).
//   decrypt-prep: rcx = round keys (in place), edx = NRounds in
//                 {10, 12, 14}.
//
// Scratch: expansion xmm0..xmm3; decrypt-prep r8..r11 / eax and
//   xmm0..xmm1.
//
// AES-NI instructions, plus pshufd / pslldq / pxor / movq forms, are
// db-encoded for broad assembler compatibility.
{$IFDEF CRYPTOLIB_AESNI_KEYSCHEDULE_INVERT}
  mov r10d, edx
  mov r9d, 1
  mov r11d, r10d
  dec r11d
@aes_imc_loop:
  cmp r9d, r11d
  ja @aes_imc_done
  mov eax, r9d
  imul rax, rax, 16
  movdqu xmm0, [rcx + rax]
  movdqa xmm1, xmm0
  db $66, $0F, $38, $DB, $C1       // aesimc xmm0, xmm1
  movdqu [rcx + rax], xmm0
  inc r9d
  jmp @aes_imc_loop
@aes_imc_done:
  xor r9d, r9d
  mov eax, r10d
@aes_swap_loop:
  cmp r9d, eax
  jge @aes_swap_done
  movsxd r11, r9d
  imul r11, r11, 16
  movsxd r8, eax
  imul r8, r8, 16
  movdqu xmm0, [rcx + r11]
  movdqu xmm1, [rcx + r8]
  movdqu [rcx + r11], xmm1
  movdqu [rcx + r8], xmm0
  inc r9d
  dec eax
  jmp @aes_swap_loop
@aes_swap_done:
{$ELSE}
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  movdqu    xmm0, [rcx]
  movdqu    [rdx], xmm0

// ----- K[1], rcon $01 -----
  db $66, $0F, $3A, $DF, $C8, $01         // aeskeygenassist xmm1, xmm0, $01
  db $66, $0F, $70, $C9, $FF              // pshufd xmm1, xmm1, $FF
  movdqa    xmm2, xmm0
  db $66, $0F, $73, $FA, $04              // pslldq xmm2, $04
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04              // pslldq xmm2, $04
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04              // pslldq xmm2, $04
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  db $66, $0F, $EF, $C1                   // pxor xmm0, xmm1
  movdqu    [rdx + 16], xmm0

// ----- K[2], rcon $02 -----
  db $66, $0F, $3A, $DF, $C8, $02         // aeskeygenassist xmm1, xmm0, $02
  db $66, $0F, $70, $C9, $FF              // pshufd xmm1, xmm1, $FF
  movdqa    xmm2, xmm0
  db $66, $0F, $73, $FA, $04              // pslldq xmm2, $04
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04              // pslldq xmm2, $04
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04              // pslldq xmm2, $04
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  db $66, $0F, $EF, $C1                   // pxor xmm0, xmm1
  movdqu    [rdx + 32], xmm0

// ----- K[3], rcon $04 -----
  db $66, $0F, $3A, $DF, $C8, $04         // aeskeygenassist xmm1, xmm0, $04
  db $66, $0F, $70, $C9, $FF              // pshufd xmm1, xmm1, $FF
  movdqa    xmm2, xmm0
  db $66, $0F, $73, $FA, $04              // pslldq xmm2, $04
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04              // pslldq xmm2, $04
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04              // pslldq xmm2, $04
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  db $66, $0F, $EF, $C1                   // pxor xmm0, xmm1
  movdqu    [rdx + 48], xmm0

// ----- K[4], rcon $08 -----
  db $66, $0F, $3A, $DF, $C8, $08         // aeskeygenassist xmm1, xmm0, $08
  db $66, $0F, $70, $C9, $FF              // pshufd xmm1, xmm1, $FF
  movdqa    xmm2, xmm0
  db $66, $0F, $73, $FA, $04              // pslldq xmm2, $04
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04              // pslldq xmm2, $04
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04              // pslldq xmm2, $04
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  db $66, $0F, $EF, $C1                   // pxor xmm0, xmm1
  movdqu    [rdx + 64], xmm0

// ----- K[5], rcon $10 -----
  db $66, $0F, $3A, $DF, $C8, $10         // aeskeygenassist xmm1, xmm0, $10
  db $66, $0F, $70, $C9, $FF              // pshufd xmm1, xmm1, $FF
  movdqa    xmm2, xmm0
  db $66, $0F, $73, $FA, $04              // pslldq xmm2, $04
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04              // pslldq xmm2, $04
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04              // pslldq xmm2, $04
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  db $66, $0F, $EF, $C1                   // pxor xmm0, xmm1
  movdqu    [rdx + 80], xmm0

// ----- K[6], rcon $20 -----
  db $66, $0F, $3A, $DF, $C8, $20         // aeskeygenassist xmm1, xmm0, $20
  db $66, $0F, $70, $C9, $FF              // pshufd xmm1, xmm1, $FF
  movdqa    xmm2, xmm0
  db $66, $0F, $73, $FA, $04              // pslldq xmm2, $04
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04              // pslldq xmm2, $04
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04              // pslldq xmm2, $04
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  db $66, $0F, $EF, $C1                   // pxor xmm0, xmm1
  movdqu    [rdx + 96], xmm0

// ----- K[7], rcon $40 -----
  db $66, $0F, $3A, $DF, $C8, $40         // aeskeygenassist xmm1, xmm0, $40
  db $66, $0F, $70, $C9, $FF              // pshufd xmm1, xmm1, $FF
  movdqa    xmm2, xmm0
  db $66, $0F, $73, $FA, $04              // pslldq xmm2, $04
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04              // pslldq xmm2, $04
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04              // pslldq xmm2, $04
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  db $66, $0F, $EF, $C1                   // pxor xmm0, xmm1
  movdqu    [rdx + 112], xmm0

// ----- K[8], rcon $80 -----
  db $66, $0F, $3A, $DF, $C8, $80         // aeskeygenassist xmm1, xmm0, $80
  db $66, $0F, $70, $C9, $FF              // pshufd xmm1, xmm1, $FF
  movdqa    xmm2, xmm0
  db $66, $0F, $73, $FA, $04              // pslldq xmm2, $04
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04              // pslldq xmm2, $04
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04              // pslldq xmm2, $04
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  db $66, $0F, $EF, $C1                   // pxor xmm0, xmm1
  movdqu    [rdx + 128], xmm0

// ----- K[9], rcon $1B -----
  db $66, $0F, $3A, $DF, $C8, $1B         // aeskeygenassist xmm1, xmm0, $1B
  db $66, $0F, $70, $C9, $FF              // pshufd xmm1, xmm1, $FF
  movdqa    xmm2, xmm0
  db $66, $0F, $73, $FA, $04              // pslldq xmm2, $04
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04              // pslldq xmm2, $04
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04              // pslldq xmm2, $04
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  db $66, $0F, $EF, $C1                   // pxor xmm0, xmm1
  movdqu    [rdx + 144], xmm0

// ----- K[10], rcon $36 -----
  db $66, $0F, $3A, $DF, $C8, $36         // aeskeygenassist xmm1, xmm0, $36
  db $66, $0F, $70, $C9, $FF              // pshufd xmm1, xmm1, $FF
  movdqa    xmm2, xmm0
  db $66, $0F, $73, $FA, $04              // pslldq xmm2, $04
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04              // pslldq xmm2, $04
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04              // pslldq xmm2, $04
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  db $66, $0F, $EF, $C1                   // pxor xmm0, xmm1
  movdqu    [rdx + 160], xmm0
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqu    xmm0, [rcx]
  db $F3, $0F, $7E, $49, $10              // movq xmm1, qword ptr [rcx + 16]
  movdqu    [rdx], xmm0
  db $66, $0F, $D6, $4A, $10              // movq qword ptr [rdx + 16], xmm1

// ----- W[6..11], rcon $01 -----
  db $66, $0F, $3A, $DF, $D1, $01         // aeskeygenassist xmm2, xmm1, $01
  db $66, $0F, $70, $D2, $55              // pshufd xmm2, xmm2, $55
  movdqa    xmm3, xmm0
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  movdqu    [rdx + 24], xmm0
  db $66, $0F, $70, $D0, $FF              // pshufd xmm2, xmm0, $FF
  movdqa    xmm3, xmm1
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $CB                   // pxor xmm1, xmm3
  db $66, $0F, $EF, $CA                   // pxor xmm1, xmm2
  db $66, $0F, $D6, $4A, $28              // movq qword ptr [rdx + 40], xmm1

// ----- W[12..17], rcon $02 -----
  db $66, $0F, $3A, $DF, $D1, $02         // aeskeygenassist xmm2, xmm1, $02
  db $66, $0F, $70, $D2, $55              // pshufd xmm2, xmm2, $55
  movdqa    xmm3, xmm0
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  movdqu    [rdx + 48], xmm0
  db $66, $0F, $70, $D0, $FF              // pshufd xmm2, xmm0, $FF
  movdqa    xmm3, xmm1
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $CB                   // pxor xmm1, xmm3
  db $66, $0F, $EF, $CA                   // pxor xmm1, xmm2
  db $66, $0F, $D6, $4A, $40              // movq qword ptr [rdx + 64], xmm1

// ----- W[18..23], rcon $04 -----
  db $66, $0F, $3A, $DF, $D1, $04         // aeskeygenassist xmm2, xmm1, $04
  db $66, $0F, $70, $D2, $55              // pshufd xmm2, xmm2, $55
  movdqa    xmm3, xmm0
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  movdqu    [rdx + 72], xmm0
  db $66, $0F, $70, $D0, $FF              // pshufd xmm2, xmm0, $FF
  movdqa    xmm3, xmm1
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $CB                   // pxor xmm1, xmm3
  db $66, $0F, $EF, $CA                   // pxor xmm1, xmm2
  db $66, $0F, $D6, $4A, $58              // movq qword ptr [rdx + 88], xmm1

// ----- W[24..29], rcon $08 -----
  db $66, $0F, $3A, $DF, $D1, $08         // aeskeygenassist xmm2, xmm1, $08
  db $66, $0F, $70, $D2, $55              // pshufd xmm2, xmm2, $55
  movdqa    xmm3, xmm0
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  movdqu    [rdx + 96], xmm0
  db $66, $0F, $70, $D0, $FF              // pshufd xmm2, xmm0, $FF
  movdqa    xmm3, xmm1
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $CB                   // pxor xmm1, xmm3
  db $66, $0F, $EF, $CA                   // pxor xmm1, xmm2
  db $66, $0F, $D6, $4A, $70              // movq qword ptr [rdx + 112], xmm1

// ----- W[30..35], rcon $10 -----
  db $66, $0F, $3A, $DF, $D1, $10         // aeskeygenassist xmm2, xmm1, $10
  db $66, $0F, $70, $D2, $55              // pshufd xmm2, xmm2, $55
  movdqa    xmm3, xmm0
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  movdqu    [rdx + 120], xmm0
  db $66, $0F, $70, $D0, $FF              // pshufd xmm2, xmm0, $FF
  movdqa    xmm3, xmm1
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $CB                   // pxor xmm1, xmm3
  db $66, $0F, $EF, $CA                   // pxor xmm1, xmm2
  db $66, $0F, $D6, $8A, $88, $00, $00, $00 // movq qword ptr [rdx + 136], xmm1

// ----- W[36..41], rcon $20 -----
  db $66, $0F, $3A, $DF, $D1, $20         // aeskeygenassist xmm2, xmm1, $20
  db $66, $0F, $70, $D2, $55              // pshufd xmm2, xmm2, $55
  movdqa    xmm3, xmm0
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  movdqu    [rdx + 144], xmm0
  db $66, $0F, $70, $D0, $FF              // pshufd xmm2, xmm0, $FF
  movdqa    xmm3, xmm1
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $CB                   // pxor xmm1, xmm3
  db $66, $0F, $EF, $CA                   // pxor xmm1, xmm2
  db $66, $0F, $D6, $8A, $A0, $00, $00, $00 // movq qword ptr [rdx + 160], xmm1

// ----- W[42..47], rcon $40 -----
  db $66, $0F, $3A, $DF, $D1, $40         // aeskeygenassist xmm2, xmm1, $40
  db $66, $0F, $70, $D2, $55              // pshufd xmm2, xmm2, $55
  movdqa    xmm3, xmm0
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  movdqu    [rdx + 168], xmm0
  db $66, $0F, $70, $D0, $FF              // pshufd xmm2, xmm0, $FF
  movdqa    xmm3, xmm1
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $CB                   // pxor xmm1, xmm3
  db $66, $0F, $EF, $CA                   // pxor xmm1, xmm2
  db $66, $0F, $D6, $8A, $B8, $00, $00, $00 // movq qword ptr [rdx + 184], xmm1

// ----- W[48..51], rcon $80 -----
  db $66, $0F, $3A, $DF, $D1, $80         // aeskeygenassist xmm2, xmm1, $80
  db $66, $0F, $70, $D2, $55              // pshufd xmm2, xmm2, $55
  movdqa    xmm3, xmm0
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  movdqu    [rdx + 192], xmm0
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqu    xmm0, [rcx]
  movdqu    xmm1, [rcx + 16]
  movdqu    [rdx], xmm0
  movdqu    [rdx + 16], xmm1

// ----- K[2], rcon $01 -----
  db $66, $0F, $3A, $DF, $D1, $01         // aeskeygenassist xmm2, xmm1, $01
  db $66, $0F, $70, $D2, $FF              // pshufd xmm2, xmm2, $FF
  movdqa    xmm3, xmm0
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  movdqu    [rdx + 32], xmm0

// ----- K[3], SubWord only -----
  db $66, $0F, $3A, $DF, $D0, $00         // aeskeygenassist xmm2, xmm0, $00
  db $66, $0F, $70, $D2, $AA              // pshufd xmm2, xmm2, $AA
  movdqa    xmm3, xmm1
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $CB                   // pxor xmm1, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $CB                   // pxor xmm1, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $CB                   // pxor xmm1, xmm3
  db $66, $0F, $EF, $CA                   // pxor xmm1, xmm2
  movdqu    [rdx + 48], xmm1

// ----- K[4], rcon $02 -----
  db $66, $0F, $3A, $DF, $D1, $02         // aeskeygenassist xmm2, xmm1, $02
  db $66, $0F, $70, $D2, $FF              // pshufd xmm2, xmm2, $FF
  movdqa    xmm3, xmm0
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  movdqu    [rdx + 64], xmm0

// ----- K[5], SubWord only -----
  db $66, $0F, $3A, $DF, $D0, $00         // aeskeygenassist xmm2, xmm0, $00
  db $66, $0F, $70, $D2, $AA              // pshufd xmm2, xmm2, $AA
  movdqa    xmm3, xmm1
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $CB                   // pxor xmm1, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $CB                   // pxor xmm1, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $CB                   // pxor xmm1, xmm3
  db $66, $0F, $EF, $CA                   // pxor xmm1, xmm2
  movdqu    [rdx + 80], xmm1

// ----- K[6], rcon $04 -----
  db $66, $0F, $3A, $DF, $D1, $04         // aeskeygenassist xmm2, xmm1, $04
  db $66, $0F, $70, $D2, $FF              // pshufd xmm2, xmm2, $FF
  movdqa    xmm3, xmm0
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  movdqu    [rdx + 96], xmm0

// ----- K[7], SubWord only -----
  db $66, $0F, $3A, $DF, $D0, $00         // aeskeygenassist xmm2, xmm0, $00
  db $66, $0F, $70, $D2, $AA              // pshufd xmm2, xmm2, $AA
  movdqa    xmm3, xmm1
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $CB                   // pxor xmm1, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $CB                   // pxor xmm1, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $CB                   // pxor xmm1, xmm3
  db $66, $0F, $EF, $CA                   // pxor xmm1, xmm2
  movdqu    [rdx + 112], xmm1

// ----- K[8], rcon $08 -----
  db $66, $0F, $3A, $DF, $D1, $08         // aeskeygenassist xmm2, xmm1, $08
  db $66, $0F, $70, $D2, $FF              // pshufd xmm2, xmm2, $FF
  movdqa    xmm3, xmm0
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  movdqu    [rdx + 128], xmm0

// ----- K[9], SubWord only -----
  db $66, $0F, $3A, $DF, $D0, $00         // aeskeygenassist xmm2, xmm0, $00
  db $66, $0F, $70, $D2, $AA              // pshufd xmm2, xmm2, $AA
  movdqa    xmm3, xmm1
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $CB                   // pxor xmm1, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $CB                   // pxor xmm1, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $CB                   // pxor xmm1, xmm3
  db $66, $0F, $EF, $CA                   // pxor xmm1, xmm2
  movdqu    [rdx + 144], xmm1

// ----- K[10], rcon $10 -----
  db $66, $0F, $3A, $DF, $D1, $10         // aeskeygenassist xmm2, xmm1, $10
  db $66, $0F, $70, $D2, $FF              // pshufd xmm2, xmm2, $FF
  movdqa    xmm3, xmm0
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  movdqu    [rdx + 160], xmm0

// ----- K[11], SubWord only -----
  db $66, $0F, $3A, $DF, $D0, $00         // aeskeygenassist xmm2, xmm0, $00
  db $66, $0F, $70, $D2, $AA              // pshufd xmm2, xmm2, $AA
  movdqa    xmm3, xmm1
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $CB                   // pxor xmm1, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $CB                   // pxor xmm1, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $CB                   // pxor xmm1, xmm3
  db $66, $0F, $EF, $CA                   // pxor xmm1, xmm2
  movdqu    [rdx + 176], xmm1

// ----- K[12], rcon $20 -----
  db $66, $0F, $3A, $DF, $D1, $20         // aeskeygenassist xmm2, xmm1, $20
  db $66, $0F, $70, $D2, $FF              // pshufd xmm2, xmm2, $FF
  movdqa    xmm3, xmm0
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  movdqu    [rdx + 192], xmm0

// ----- K[13], SubWord only -----
  db $66, $0F, $3A, $DF, $D0, $00         // aeskeygenassist xmm2, xmm0, $00
  db $66, $0F, $70, $D2, $AA              // pshufd xmm2, xmm2, $AA
  movdqa    xmm3, xmm1
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $CB                   // pxor xmm1, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $CB                   // pxor xmm1, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $CB                   // pxor xmm1, xmm3
  db $66, $0F, $EF, $CA                   // pxor xmm1, xmm2
  movdqu    [rdx + 208], xmm1

// ----- K[14], rcon $40 -----
  db $66, $0F, $3A, $DF, $D1, $40         // aeskeygenassist xmm2, xmm1, $40
  db $66, $0F, $70, $D2, $FF              // pshufd xmm2, xmm2, $FF
  movdqa    xmm3, xmm0
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04              // pslldq xmm3, $04
  db $66, $0F, $EF, $C3                   // pxor xmm0, xmm3
  db $66, $0F, $EF, $C2                   // pxor xmm0, xmm2
  movdqu    [rdx + 224], xmm0
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}
{$ENDIF}
