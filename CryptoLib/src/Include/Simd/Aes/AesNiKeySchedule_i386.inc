// AES-NI key-schedule kernel, merged expansion + decrypt-prep, merged key sizes (i386).
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
// Entry (after ClpSimdProc2Begin_i386.inc):
//   expansion:    ebx = user key (16 / 24 / 32 bytes),
//                 esi = KeysOut (16 * (N_R + 1) bytes).
//   decrypt-prep: ebx = round keys (in place), esi = NRounds in
//                 {10, 12, 14}; pushes/pops edi and remaps
//                 internally to ecx = keys, ebx = nrounds.
//
// Scratch: expansion xmm0..xmm3; decrypt-prep esi / edi / eax / edx
//   and xmm0..xmm1. The epilogue pops esi / ebx.
//
// AES-NI instructions, plus pshufd / pslldq / pxor / movq forms, are
// db-encoded for broad assembler compatibility.
{$IFDEF CRYPTOLIB_AESNI_KEYSCHEDULE_INVERT}
  push edi
  mov ecx, ebx
  mov ebx, esi
  mov esi, 1
  mov edi, ebx
  dec edi
@aes_imc_loop:
  cmp esi, edi
  ja @aes_imc_done
  mov eax, esi
  shl eax, 4
  movdqu xmm0, [ecx + eax]
  movdqa xmm1, xmm0
  db $66, $0F, $38, $DB, $C1       // aesimc xmm0, xmm1
  movdqu [ecx + eax], xmm0
  inc esi
  jmp @aes_imc_loop
@aes_imc_done:
  xor esi, esi
  mov eax, ebx
@aes_swap_loop:
  cmp esi, eax
  jge @aes_swap_done
  mov edx, esi
  shl edx, 4
  mov edi, eax
  shl edi, 4
  movdqu xmm0, [ecx + edx]
  movdqu xmm1, [ecx + edi]
  movdqu [ecx + edx], xmm1
  movdqu [ecx + edi], xmm0
  inc esi
  dec eax
  jmp @aes_swap_loop
@aes_swap_done:
  pop edi
{$ELSE}
{$IFDEF CRYPTOLIB_AESNI_KEY128}
  movdqu    xmm0, [ebx + 0]
  movdqu    [esi + 0], xmm0

// ----- K[1], rcon $01 -----
  db $66, $0F, $3A, $DF, $C8, $01   // aeskeygenassist xmm1, xmm0, $01
  db $66, $0F, $70, $C9, $FF   // pshufd xmm1, xmm1, $FF
  movdqa    xmm2, xmm0
  db $66, $0F, $73, $FA, $04   // pslldq xmm2, $04
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04   // pslldq xmm2, $04
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04   // pslldq xmm2, $04
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  db $66, $0F, $EF, $C1   // pxor xmm0, xmm1
  movdqu    [esi + 16], xmm0

// ----- K[2], rcon $02 -----
  db $66, $0F, $3A, $DF, $C8, $02   // aeskeygenassist xmm1, xmm0, $02
  db $66, $0F, $70, $C9, $FF   // pshufd xmm1, xmm1, $FF
  movdqa    xmm2, xmm0
  db $66, $0F, $73, $FA, $04   // pslldq xmm2, $04
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04   // pslldq xmm2, $04
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04   // pslldq xmm2, $04
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  db $66, $0F, $EF, $C1   // pxor xmm0, xmm1
  movdqu    [esi + 32], xmm0

// ----- K[3], rcon $04 -----
  db $66, $0F, $3A, $DF, $C8, $04   // aeskeygenassist xmm1, xmm0, $04
  db $66, $0F, $70, $C9, $FF   // pshufd xmm1, xmm1, $FF
  movdqa    xmm2, xmm0
  db $66, $0F, $73, $FA, $04   // pslldq xmm2, $04
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04   // pslldq xmm2, $04
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04   // pslldq xmm2, $04
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  db $66, $0F, $EF, $C1   // pxor xmm0, xmm1
  movdqu    [esi + 48], xmm0

// ----- K[4], rcon $08 -----
  db $66, $0F, $3A, $DF, $C8, $08   // aeskeygenassist xmm1, xmm0, $08
  db $66, $0F, $70, $C9, $FF   // pshufd xmm1, xmm1, $FF
  movdqa    xmm2, xmm0
  db $66, $0F, $73, $FA, $04   // pslldq xmm2, $04
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04   // pslldq xmm2, $04
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04   // pslldq xmm2, $04
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  db $66, $0F, $EF, $C1   // pxor xmm0, xmm1
  movdqu    [esi + 64], xmm0

// ----- K[5], rcon $10 -----
  db $66, $0F, $3A, $DF, $C8, $10   // aeskeygenassist xmm1, xmm0, $10
  db $66, $0F, $70, $C9, $FF   // pshufd xmm1, xmm1, $FF
  movdqa    xmm2, xmm0
  db $66, $0F, $73, $FA, $04   // pslldq xmm2, $04
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04   // pslldq xmm2, $04
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04   // pslldq xmm2, $04
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  db $66, $0F, $EF, $C1   // pxor xmm0, xmm1
  movdqu    [esi + 80], xmm0

// ----- K[6], rcon $20 -----
  db $66, $0F, $3A, $DF, $C8, $20   // aeskeygenassist xmm1, xmm0, $20
  db $66, $0F, $70, $C9, $FF   // pshufd xmm1, xmm1, $FF
  movdqa    xmm2, xmm0
  db $66, $0F, $73, $FA, $04   // pslldq xmm2, $04
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04   // pslldq xmm2, $04
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04   // pslldq xmm2, $04
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  db $66, $0F, $EF, $C1   // pxor xmm0, xmm1
  movdqu    [esi + 96], xmm0

// ----- K[7], rcon $40 -----
  db $66, $0F, $3A, $DF, $C8, $40   // aeskeygenassist xmm1, xmm0, $40
  db $66, $0F, $70, $C9, $FF   // pshufd xmm1, xmm1, $FF
  movdqa    xmm2, xmm0
  db $66, $0F, $73, $FA, $04   // pslldq xmm2, $04
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04   // pslldq xmm2, $04
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04   // pslldq xmm2, $04
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  db $66, $0F, $EF, $C1   // pxor xmm0, xmm1
  movdqu    [esi + 112], xmm0

// ----- K[8], rcon $80 -----
  db $66, $0F, $3A, $DF, $C8, $80   // aeskeygenassist xmm1, xmm0, $80
  db $66, $0F, $70, $C9, $FF   // pshufd xmm1, xmm1, $FF
  movdqa    xmm2, xmm0
  db $66, $0F, $73, $FA, $04   // pslldq xmm2, $04
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04   // pslldq xmm2, $04
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04   // pslldq xmm2, $04
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  db $66, $0F, $EF, $C1   // pxor xmm0, xmm1
  movdqu    [esi + 128], xmm0

// ----- K[9], rcon $1B -----
  db $66, $0F, $3A, $DF, $C8, $1B   // aeskeygenassist xmm1, xmm0, $1B
  db $66, $0F, $70, $C9, $FF   // pshufd xmm1, xmm1, $FF
  movdqa    xmm2, xmm0
  db $66, $0F, $73, $FA, $04   // pslldq xmm2, $04
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04   // pslldq xmm2, $04
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04   // pslldq xmm2, $04
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  db $66, $0F, $EF, $C1   // pxor xmm0, xmm1
  movdqu    [esi + 144], xmm0

// ----- K[10], rcon $36 -----
  db $66, $0F, $3A, $DF, $C8, $36   // aeskeygenassist xmm1, xmm0, $36
  db $66, $0F, $70, $C9, $FF   // pshufd xmm1, xmm1, $FF
  movdqa    xmm2, xmm0
  db $66, $0F, $73, $FA, $04   // pslldq xmm2, $04
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04   // pslldq xmm2, $04
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  db $66, $0F, $73, $FA, $04   // pslldq xmm2, $04
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  db $66, $0F, $EF, $C1   // pxor xmm0, xmm1
  movdqu    [esi + 160], xmm0
{$ELSE}
  {$IFDEF CRYPTOLIB_AESNI_KEY192}
  movdqu    xmm0, [ebx + 0]
  db $F3, $0F, $7E, $4B, $10   // movq xmm1, qword ptr [ebx + 16]
  movdqu    [esi + 0], xmm0
  db $66, $0F, $D6, $4E, $10   // movq qword ptr [esi + 16], xmm1

// ----- W[6..11], rcon $01 -----
  db $66, $0F, $3A, $DF, $D1, $01   // aeskeygenassist xmm2, xmm1, $01
  db $66, $0F, $70, $D2, $55   // pshufd xmm2, xmm2, $55
  movdqa    xmm3, xmm0
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  movdqu    [esi + 24], xmm0
  db $66, $0F, $70, $D0, $FF   // pshufd xmm2, xmm0, $FF
  movdqa    xmm3, xmm1
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $CB   // pxor xmm1, xmm3
  db $66, $0F, $EF, $CA   // pxor xmm1, xmm2
  db $66, $0F, $D6, $4E, $28   // movq qword ptr [esi + 40], xmm1

// ----- W[12..17], rcon $02 -----
  db $66, $0F, $3A, $DF, $D1, $02   // aeskeygenassist xmm2, xmm1, $02
  db $66, $0F, $70, $D2, $55   // pshufd xmm2, xmm2, $55
  movdqa    xmm3, xmm0
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  movdqu    [esi + 48], xmm0
  db $66, $0F, $70, $D0, $FF   // pshufd xmm2, xmm0, $FF
  movdqa    xmm3, xmm1
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $CB   // pxor xmm1, xmm3
  db $66, $0F, $EF, $CA   // pxor xmm1, xmm2
  db $66, $0F, $D6, $4E, $40   // movq qword ptr [esi + 64], xmm1

// ----- W[18..23], rcon $04 -----
  db $66, $0F, $3A, $DF, $D1, $04   // aeskeygenassist xmm2, xmm1, $04
  db $66, $0F, $70, $D2, $55   // pshufd xmm2, xmm2, $55
  movdqa    xmm3, xmm0
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  movdqu    [esi + 72], xmm0
  db $66, $0F, $70, $D0, $FF   // pshufd xmm2, xmm0, $FF
  movdqa    xmm3, xmm1
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $CB   // pxor xmm1, xmm3
  db $66, $0F, $EF, $CA   // pxor xmm1, xmm2
  db $66, $0F, $D6, $4E, $58   // movq qword ptr [esi + 88], xmm1

// ----- W[24..29], rcon $08 -----
  db $66, $0F, $3A, $DF, $D1, $08   // aeskeygenassist xmm2, xmm1, $08
  db $66, $0F, $70, $D2, $55   // pshufd xmm2, xmm2, $55
  movdqa    xmm3, xmm0
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  movdqu    [esi + 96], xmm0
  db $66, $0F, $70, $D0, $FF   // pshufd xmm2, xmm0, $FF
  movdqa    xmm3, xmm1
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $CB   // pxor xmm1, xmm3
  db $66, $0F, $EF, $CA   // pxor xmm1, xmm2
  db $66, $0F, $D6, $4E, $70   // movq qword ptr [esi + 112], xmm1

// ----- W[30..35], rcon $10 -----
  db $66, $0F, $3A, $DF, $D1, $10   // aeskeygenassist xmm2, xmm1, $10
  db $66, $0F, $70, $D2, $55   // pshufd xmm2, xmm2, $55
  movdqa    xmm3, xmm0
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  movdqu    [esi + 120], xmm0
  db $66, $0F, $70, $D0, $FF   // pshufd xmm2, xmm0, $FF
  movdqa    xmm3, xmm1
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $CB   // pxor xmm1, xmm3
  db $66, $0F, $EF, $CA   // pxor xmm1, xmm2
  db $66, $0F, $D6, $8E, $88, $00, $00, $00   // movq qword ptr [esi + 136], xmm1

// ----- W[36..41], rcon $20 -----
  db $66, $0F, $3A, $DF, $D1, $20   // aeskeygenassist xmm2, xmm1, $20
  db $66, $0F, $70, $D2, $55   // pshufd xmm2, xmm2, $55
  movdqa    xmm3, xmm0
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  movdqu    [esi + 144], xmm0
  db $66, $0F, $70, $D0, $FF   // pshufd xmm2, xmm0, $FF
  movdqa    xmm3, xmm1
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $CB   // pxor xmm1, xmm3
  db $66, $0F, $EF, $CA   // pxor xmm1, xmm2
  db $66, $0F, $D6, $8E, $A0, $00, $00, $00   // movq qword ptr [esi + 160], xmm1

// ----- W[42..47], rcon $40 -----
  db $66, $0F, $3A, $DF, $D1, $40   // aeskeygenassist xmm2, xmm1, $40
  db $66, $0F, $70, $D2, $55   // pshufd xmm2, xmm2, $55
  movdqa    xmm3, xmm0
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  movdqu    [esi + 168], xmm0
  db $66, $0F, $70, $D0, $FF   // pshufd xmm2, xmm0, $FF
  movdqa    xmm3, xmm1
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $CB   // pxor xmm1, xmm3
  db $66, $0F, $EF, $CA   // pxor xmm1, xmm2
  db $66, $0F, $D6, $8E, $B8, $00, $00, $00   // movq qword ptr [esi + 184], xmm1

// ----- W[48..51], rcon $80 -----
  db $66, $0F, $3A, $DF, $D1, $80   // aeskeygenassist xmm2, xmm1, $80
  db $66, $0F, $70, $D2, $55   // pshufd xmm2, xmm2, $55
  movdqa    xmm3, xmm0
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  movdqu    [esi + 192], xmm0
  {$ELSE}
    {$IFDEF CRYPTOLIB_AESNI_KEY256}
  movdqu    xmm0, [ebx + 0]
  movdqu    xmm1, [ebx + 16]
  movdqu    [esi + 0], xmm0
  movdqu    [esi + 16], xmm1

// ----- K[2], rcon $01 -----
  db $66, $0F, $3A, $DF, $D1, $01   // aeskeygenassist xmm2, xmm1, $01
  db $66, $0F, $70, $D2, $FF   // pshufd xmm2, xmm2, $FF
  movdqa    xmm3, xmm0
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  movdqu    [esi + 32], xmm0

// ----- K[3], SubWord only -----
  db $66, $0F, $3A, $DF, $D0, $00   // aeskeygenassist xmm2, xmm0, $00
  db $66, $0F, $70, $D2, $AA   // pshufd xmm2, xmm2, $AA
  movdqa    xmm3, xmm1
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $CB   // pxor xmm1, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $CB   // pxor xmm1, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $CB   // pxor xmm1, xmm3
  db $66, $0F, $EF, $CA   // pxor xmm1, xmm2
  movdqu    [esi + 48], xmm1

// ----- K[4], rcon $02 -----
  db $66, $0F, $3A, $DF, $D1, $02   // aeskeygenassist xmm2, xmm1, $02
  db $66, $0F, $70, $D2, $FF   // pshufd xmm2, xmm2, $FF
  movdqa    xmm3, xmm0
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  movdqu    [esi + 64], xmm0

// ----- K[5], SubWord only -----
  db $66, $0F, $3A, $DF, $D0, $00   // aeskeygenassist xmm2, xmm0, $00
  db $66, $0F, $70, $D2, $AA   // pshufd xmm2, xmm2, $AA
  movdqa    xmm3, xmm1
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $CB   // pxor xmm1, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $CB   // pxor xmm1, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $CB   // pxor xmm1, xmm3
  db $66, $0F, $EF, $CA   // pxor xmm1, xmm2
  movdqu    [esi + 80], xmm1

// ----- K[6], rcon $04 -----
  db $66, $0F, $3A, $DF, $D1, $04   // aeskeygenassist xmm2, xmm1, $04
  db $66, $0F, $70, $D2, $FF   // pshufd xmm2, xmm2, $FF
  movdqa    xmm3, xmm0
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  movdqu    [esi + 96], xmm0

// ----- K[7], SubWord only -----
  db $66, $0F, $3A, $DF, $D0, $00   // aeskeygenassist xmm2, xmm0, $00
  db $66, $0F, $70, $D2, $AA   // pshufd xmm2, xmm2, $AA
  movdqa    xmm3, xmm1
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $CB   // pxor xmm1, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $CB   // pxor xmm1, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $CB   // pxor xmm1, xmm3
  db $66, $0F, $EF, $CA   // pxor xmm1, xmm2
  movdqu    [esi + 112], xmm1

// ----- K[8], rcon $08 -----
  db $66, $0F, $3A, $DF, $D1, $08   // aeskeygenassist xmm2, xmm1, $08
  db $66, $0F, $70, $D2, $FF   // pshufd xmm2, xmm2, $FF
  movdqa    xmm3, xmm0
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  movdqu    [esi + 128], xmm0

// ----- K[9], SubWord only -----
  db $66, $0F, $3A, $DF, $D0, $00   // aeskeygenassist xmm2, xmm0, $00
  db $66, $0F, $70, $D2, $AA   // pshufd xmm2, xmm2, $AA
  movdqa    xmm3, xmm1
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $CB   // pxor xmm1, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $CB   // pxor xmm1, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $CB   // pxor xmm1, xmm3
  db $66, $0F, $EF, $CA   // pxor xmm1, xmm2
  movdqu    [esi + 144], xmm1

// ----- K[10], rcon $10 -----
  db $66, $0F, $3A, $DF, $D1, $10   // aeskeygenassist xmm2, xmm1, $10
  db $66, $0F, $70, $D2, $FF   // pshufd xmm2, xmm2, $FF
  movdqa    xmm3, xmm0
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  movdqu    [esi + 160], xmm0

// ----- K[11], SubWord only -----
  db $66, $0F, $3A, $DF, $D0, $00   // aeskeygenassist xmm2, xmm0, $00
  db $66, $0F, $70, $D2, $AA   // pshufd xmm2, xmm2, $AA
  movdqa    xmm3, xmm1
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $CB   // pxor xmm1, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $CB   // pxor xmm1, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $CB   // pxor xmm1, xmm3
  db $66, $0F, $EF, $CA   // pxor xmm1, xmm2
  movdqu    [esi + 176], xmm1

// ----- K[12], rcon $20 -----
  db $66, $0F, $3A, $DF, $D1, $20   // aeskeygenassist xmm2, xmm1, $20
  db $66, $0F, $70, $D2, $FF   // pshufd xmm2, xmm2, $FF
  movdqa    xmm3, xmm0
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  movdqu    [esi + 192], xmm0

// ----- K[13], SubWord only -----
  db $66, $0F, $3A, $DF, $D0, $00   // aeskeygenassist xmm2, xmm0, $00
  db $66, $0F, $70, $D2, $AA   // pshufd xmm2, xmm2, $AA
  movdqa    xmm3, xmm1
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $CB   // pxor xmm1, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $CB   // pxor xmm1, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $CB   // pxor xmm1, xmm3
  db $66, $0F, $EF, $CA   // pxor xmm1, xmm2
  movdqu    [esi + 208], xmm1

// ----- K[14], rcon $40 -----
  db $66, $0F, $3A, $DF, $D1, $40   // aeskeygenassist xmm2, xmm1, $40
  db $66, $0F, $70, $D2, $FF   // pshufd xmm2, xmm2, $FF
  movdqa    xmm3, xmm0
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $73, $FB, $04   // pslldq xmm3, $04
  db $66, $0F, $EF, $C3   // pxor xmm0, xmm3
  db $66, $0F, $EF, $C2   // pxor xmm0, xmm2
  movdqu    [esi + 224], xmm0
    {$ELSE}
    {$FATAL Exactly one of CRYPTOLIB_AESNI_KEY128, CRYPTOLIB_AESNI_KEY192, CRYPTOLIB_AESNI_KEY256 must be defined before including this file}
    {$ENDIF}
  {$ENDIF}
{$ENDIF}
{$ENDIF}
  pop       esi
  pop       ebx
