// ChaCha7539 (IETF) 128B (two 64B blocks), fused I/O, pure SSE2 (x86-64).
// -------------------------------------------------------------------
// Little-endian state in [rdx].
// Fused I/O xor: read plaintext at AIn (r8), xor with ChaCha output, write
// to AOut (r9) - no 64B LK/keystream temp in Pascal.
//
// On entry (after ClpSimdProc4Begin_x86_64.inc):
//   rcx = ARounds, rdx = AState (R/W, 16 UInt32), r8 = AIn, r9 = AOut.
//
// Word 12 at [rdx+48] is advanced by 2 (once per 64B block). On 32-bit
// counter wrap to 0, calls ChaCha7539RaiseCounter7539.
//
// Reference: RFC 7539 (IETF ChaCha20, superseded by RFC 8439) - the
// 32-bit-counter/96-bit-nonce state layout that this kernel operates on;
// quarter-round arithmetic per D.J. Bernstein, "ChaCha, a variant of
// Salsa20".
  mov     r11, rcx
  // --- block 1 (counter C in memory) ---
  sub     rsp, 64
  movdqu  xmm0, [rdx+0]
  movdqu  xmm1, [rdx+16]
  movdqu  xmm2, [rdx+32]
  movdqu  xmm3, [rdx+48]
  movdqu  [rsp], xmm0
  movdqu  [rsp+16], xmm1
  movdqu  [rsp+32], xmm2
  movdqu  [rsp+48], xmm3
  mov     r10, r11
@@c53b1r:
  { ---- inline: shared SSE2 double round (column + diagonal) ---- }
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  psrld   xmm3, 16
  pslld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  psrld   xmm1, 20
  pslld   xmm4, 12
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  psrld   xmm3, 24
  pslld   xmm4, 8
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  psrld   xmm1, 25
  pslld   xmm4, 7
  por     xmm1, xmm4
  pshufd  xmm1, xmm1, $39
  pshufd  xmm2, xmm2, $4E
  pshufd  xmm3, xmm3, $93
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  psrld   xmm3, 16
  pslld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  psrld   xmm1, 20
  pslld   xmm4, 12
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  psrld   xmm3, 24
  pslld   xmm4, 8
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  psrld   xmm1, 25
  pslld   xmm4, 7
  por     xmm1, xmm4
  pshufd  xmm1, xmm1, $93
  pshufd  xmm2, xmm2, $4E
  pshufd  xmm3, xmm3, $39
  sub     r10, 2
  jg      @@c53b1r
  movdqu  xmm4, [rsp+0]
  paddd   xmm0, xmm4
  movdqu  xmm4, [rsp+16]
  paddd   xmm1, xmm4
  movdqu  xmm4, [rsp+32]
  paddd   xmm2, xmm4
  movdqu  xmm4, [rsp+48]
  paddd   xmm3, xmm4
  add     rsp, 64
  movdqu  xmm4, [r8+0]
  pxor    xmm0, xmm4
  movdqu  [r9+0], xmm0
  movdqu  xmm4, [r8+16]
  pxor    xmm1, xmm4
  movdqu  [r9+16], xmm1
  movdqu  xmm4, [r8+32]
  pxor    xmm2, xmm4
  movdqu  [r9+32], xmm2
  movdqu  xmm4, [r8+48]
  pxor    xmm3, xmm4
  movdqu  [r9+48], xmm3
  add     dword [rdx+48], 1
  jz      @@c53bad
  // --- block 2 (counter C+1 in memory) ---
  sub     rsp, 64
  movdqu  xmm0, [rdx+0]
  movdqu  xmm1, [rdx+16]
  movdqu  xmm2, [rdx+32]
  movdqu  xmm3, [rdx+48]
  movdqu  [rsp], xmm0
  movdqu  [rsp+16], xmm1
  movdqu  [rsp+32], xmm2
  movdqu  [rsp+48], xmm3
  mov     r10, r11
@@c53b2r:
  { ---- inline: shared SSE2 double round (column + diagonal) ---- }
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  psrld   xmm3, 16
  pslld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  psrld   xmm1, 20
  pslld   xmm4, 12
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  psrld   xmm3, 24
  pslld   xmm4, 8
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  psrld   xmm1, 25
  pslld   xmm4, 7
  por     xmm1, xmm4
  pshufd  xmm1, xmm1, $39
  pshufd  xmm2, xmm2, $4E
  pshufd  xmm3, xmm3, $93
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  psrld   xmm3, 16
  pslld   xmm4, 16
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  psrld   xmm1, 20
  pslld   xmm4, 12
  por     xmm1, xmm4
  paddd   xmm0, xmm1
  pxor    xmm3, xmm0
  movdqa  xmm4, xmm3
  psrld   xmm3, 24
  pslld   xmm4, 8
  por     xmm3, xmm4
  paddd   xmm2, xmm3
  pxor    xmm1, xmm2
  movdqa  xmm4, xmm1
  psrld   xmm1, 25
  pslld   xmm4, 7
  por     xmm1, xmm4
  pshufd  xmm1, xmm1, $93
  pshufd  xmm2, xmm2, $4E
  pshufd  xmm3, xmm3, $39
  sub     r10, 2
  jg      @@c53b2r
  movdqu  xmm4, [rsp+0]
  paddd   xmm0, xmm4
  movdqu  xmm4, [rsp+16]
  paddd   xmm1, xmm4
  movdqu  xmm4, [rsp+32]
  paddd   xmm2, xmm4
  movdqu  xmm4, [rsp+48]
  paddd   xmm3, xmm4
  add     rsp, 64
  movdqu  xmm4, [r8+64]
  pxor    xmm0, xmm4
  movdqu  [r9+64], xmm0
  movdqu  xmm4, [r8+80]
  pxor    xmm1, xmm4
  movdqu  [r9+80], xmm1
  movdqu  xmm4, [r8+96]
  pxor    xmm2, xmm4
  movdqu  [r9+96], xmm2
  movdqu  xmm4, [r8+112]
  pxor    xmm3, xmm4
  movdqu  [r9+112], xmm3
  add     dword [rdx+48], 1
  jz      @@c53bad
  jmp     @@c53done
@@c53bad:
  call    ChaCha7539RaiseCounter7539
@@c53done:


