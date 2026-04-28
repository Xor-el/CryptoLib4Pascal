// SSSE3 16-byte byte-reverse utility (x86-64).
// After SimdProc3Begin_x86_64.inc: rcx = PDst, rdx = PSrc, r8 = PShuffleCtrl.
// Computes [rcx] := pshufb([rdx], [r8]).
// Uses xmm0 (data) and xmm1 (control).
//
  movdqu    xmm0, [rdx]
  movdqu    xmm1, [r8]
  pshufb    xmm0, xmm1
  movdqu    [rcx], xmm0
